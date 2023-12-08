##############################################################################
#
# Copyright (c) 2023 Jens Vagelpohl and Contributors. All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
##############################################################################
""" Configuration support for PySAML2-style configurations as JSON
"""

import json
import operator
import os
import pprint

from AccessControl import ClassSecurityInfo
from AccessControl.class_init import InitializeClass
from AccessControl.Permissions import manage_users


class PySAML2ConfigurationSupport:
    """ SAML 2.0 base plugin class """

    security = ClassSecurityInfo()
    _v_configuration = None

    #
    # ZMI helpers
    #
    @security.protected(manage_users)
    def getConfigurationFileName(self):
        """ Get the fixed configuration file name for this plugin instance """
        return f'saml2plugin_{self._uid}.json'

    @security.protected(manage_users)
    def getConfigurationFolderPath(self):
        """ Get the configuration folder path.

        This path is configured globally for each Zope instance in the Zope
        instance configuration file, normally named ``zope.conf``.
        """
        return self._configuration_folder

    @security.protected(manage_users)
    def getConfigurationFilePath(self):
        """ Get the full configuration file path for this plugin instance.

        Returns None if the configuration folder path is not configured.
        """
        if self.getConfigurationFolderPath() is None:
            return None

        file_path = os.path.join(self.getConfigurationFolderPath(),
                                 self.getConfigurationFileName())
        return os.path.abspath(file_path)

    @security.protected(manage_users)
    def haveConfigurationFile(self):
        """ Returns True if a configuration file exists, False otherwise. """
        if not self.getConfigurationFolderPath():
            return False

        return os.path.isfile(self.getConfigurationFilePath())

    @security.protected(manage_users)
    def getConfigurationZMIRepresentation(self):
        """ Returns a configuration representation for the ZMI """
        try:
            configuration = self.getConfiguration()
        except OSError as exc:
            return f'Cannot open configuraton file:\n{exc}'
        except ValueError as exc:
            return f'Bad configuration:\n{exc}'

        return pprint.pformat(configuration)

    @security.protected(manage_users)
    def getConfigurationErrors(self):
        """ Check the configuration for errors

        Returns:
            A list of mappings containing the problematic configuration key,
            the problem severity and an explanatory message.
        """
        errors = []
        try:
            configuration = self.getConfiguration()
        except Exception as exc:
            return [{'key': '-',
                     'severity': 'fatal',
                     'description': f'Cannot load configuration: {exc}'}]

        # Check if certificate and key files are configured and readable
        cert_file = configuration.get('cert_file', None)
        if cert_file and not os.path.isfile(os.path.abspath(cert_file)):
            errors.append(
                {'key': 'cert_file',
                 'severity': 'error',
                 'description': f'Cannot read certificate file {cert_file}'})

        key_file = configuration.get('key_file', None)
        if key_file and not os.path.isfile(os.path.abspath(key_file)):
            errors.append(
                {'key': 'key_file',
                 'severity': 'error',
                 'description': f'Cannot read private key file {key_file}'})

        if self.metadata_sign and (not cert_file or not key_file):
            msg = 'Missing key and certificate file paths for signing'
            errors.append(
                {'key': 'cert_file',
                 'severity': 'error',
                 'description': msg})

        # The ``xmlsec1`` binary must be available
        xmlsec_binary = configuration.get('xmlsec_binary', None)
        if not xmlsec_binary:
            errors.append(
                {'key': 'xmlsec_binary',
                 'severity': 'error',
                 'description': 'Missing xmlsec1 binary path'})
        elif not os.path.isfile(xmlsec_binary):
            msg = f'Invalid xmlsec1 binary path {xmlsec_binary}'
            errors.append(
                {'key': 'xmlsec_binary',
                 'severity': 'error',
                 'description': msg})

        # Check IdP metadata configuration if it exists
        metadata_config = configuration.get('metadata', {})
        local_md_configs = metadata_config.get('local', [])
        remote_md_configs = metadata_config.get('remote', [])

        for xml_path in local_md_configs:
            if not os.path.isfile(xml_path):
                msg = f'Cannot read IdP configuration data at {xml_path}'
                errors.append(
                    {'key': 'local',
                     'severity': 'error',
                     'description': msg})

        for remote_config in remote_md_configs:
            cert_path = remote_config.get('cert')
            if cert_path and not os.path.isfile(os.path.abspath(cert_path)):
                msg = f'Cannot read public IdP certificate at {cert_path}'
                errors.append(
                    {'key': 'cert',
                     'severity': 'error',
                     'description': msg})

        # Check local attribute conversion maps folder path if it is configured
        attribute_maps = configuration.get('attribute_maps', None)
        if attribute_maps and \
           not os.path.isdir(os.path.abspath(attribute_maps)):
            msg = f'Invalid attribute maps folder {attribute_maps}'
            errors.append(
                {'key': 'attribute_maps',
                 'severity': 'error',
                 'description': msg})

        # If an organization is configured, it must have "name" and "url"
        org = configuration.get('organization', None)
        if org and ('name' not in org or 'url' not in org):
            msg = 'Organization definitions must have "name" and "url" keys'
            errors.append(
                {'key': 'organization',
                 'severity': 'error',
                 'description': msg})

        return sorted(errors, key=operator.itemgetter('key'))

    @security.private
    def getConfiguration(self, key=None, reload=False):
        """ Read SAML configuration keys from the instance or from a file.

        The configuration file is expected to be JSON and the keys and values
        correspond to the ``pysaml2`` configuration, see
        https://pysaml2.readthedocs.io/en/latest/howto/config.html. There's
        one difference: The examples in the pysaml2 documentation import some
        string values from the pysaml2 module for convenience, like
        ``BINDING_HTTP_REDIRECT``. In the JSON file you must use the real value
        string, like 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'.

        Stores the extracted configuration values in an instance-level
        mapping for easy retrieval later.

        Args:
            key (str or None): A configuration key from the configuration file.
              If no key is provided, return the entire configuration.

        Raises ``OSError`` if the configuration file does not exist

        Raises ``ValueError`` if the configuration file is malformed

        Raises ``KeyError`` if the configuration does not contain the key
        """
        if self._v_configuration is None or reload is True:
            if self.getConfigurationFolderPath() is None:
                raise ValueError('No configuration folder path set')

            self._v_configuration = self._load_configuration_file()

        if key is None:
            return self._v_configuration

        return self._v_configuration[key]

    def _load_configuration_file(self):
        """ Load a pysaml2 configuration as JSON
        """
        configuration_path = os.path.join(self.getConfigurationFolderPath(),
                                          self.getConfigurationFileName())
        with open(configuration_path, 'r') as fp:
            try:
                configuration = json.load(fp)
            except json.JSONDecodeError as exc:
                raise ValueError('Malformed configuration file at '
                                 f'{configuration_path}: {str(exc)}')

        return configuration


InitializeClass(PySAML2ConfigurationSupport)
