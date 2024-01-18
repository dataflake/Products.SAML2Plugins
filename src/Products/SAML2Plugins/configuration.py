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

import copy
import importlib
import logging
import operator
import os
import pprint
import sys

from saml2.config import Config

from AccessControl import ClassSecurityInfo
from AccessControl.class_init import InitializeClass
from AccessControl.Permissions import manage_users
from App.config import getConfiguration


logger = logging.getLogger('Products.SAML2Plugins')
CONFIGS = {}


def getPySAML2Configuration(uid):
    """ Retrieve a PySAML2 configuration by plugin UID

    Args:
        uid (str): The plugin UID

    Returns:
        A PySAML2 configuration object or None
    """
    return CONFIGS.get(f'pysaml2_{uid}', None)


def setPySAML2Configuration(uid, config):
    """ Cache a PySAML2 configuration object

    Args:
        uid (str): A unique identifier (the plugin UID)

        config (saml2.config.Config or None):
            A PySAML2 configuration instance or None to clear it
    """
    CONFIGS[f'pysaml2_{uid}'] = config


def clearConfigurationCaches():
    """ Clear all cached configurations """
    CONFIGS.clear()


class PySAML2ConfigurationSupport:
    """ SAML 2.0 base plugin class """

    security = ClassSecurityInfo()

    _configuration = None

    #
    # ZMI helpers
    #
    @security.protected(manage_users)
    def getAttributeMaps(self):
        """ Get the attribute conversion maps from the configuration """
        name_formats = {}
        pysaml2_cfg = self.getPySAML2Configuration()

        if pysaml2_cfg is not None:
            for attr_converter in pysaml2_cfg.attribute_converters:
                mappings = name_formats.setdefault(
                            attr_converter.name_format, [])
                for key, value in attr_converter._fro.items():
                    mappings.append({'from': key, 'to': value})

        return tuple([{'name_format': name_format, 'maps': maps} for
                      name_format, maps in name_formats.items()])

    @security.protected(manage_users)
    def getConfigurationFileName(self):
        """ Get the fixed configuration file name for this plugin instance """
        return f'saml2_cfg_{self._uid}.py'

    @security.private
    def getConfigurationModuleName(self):
        """ Get the configuration module name for importing it """
        return os.path.splitext(self.getConfigurationFileName())[0]

    @security.protected(manage_users)
    def getConfigurationFolderPath(self):
        """ Get the configuration folder path.

        This path is configured globally for each Zope instance in the Zope
        instance configuration file, normally named ``zope.conf``. If it is
        not set, the ``etc`` folder inside the Zope instance home folder is
        used as default.

        Returns:
            A filesystem folder path
        """
        if self._configuration_folder is None:
            # The configuration folder can be set in a zope.conf
            # `product-config` section
            zope_config = getConfiguration()
            default_folder = os.path.join(zope_config.instancehome, 'etc')

            product_config = getattr(zope_config, 'product_config', dict())
            my_config = product_config.get('saml2plugins', dict())
            self._configuration_folder = my_config.get('configuration_folder',
                                                       default_folder)
        return self._configuration_folder

    @security.protected(manage_users)
    def getConfigurationFilePath(self):
        """ Get the full configuration file path for this plugin instance.
        """
        file_path = os.path.join(self.getConfigurationFolderPath(),
                                 self.getConfigurationFileName())
        return os.path.abspath(file_path)

    @security.protected(manage_users)
    def haveConfigurationFile(self):
        """ Returns True if a configuration file exists, False otherwise. """
        return os.path.isfile(self.getConfigurationFilePath())

    @security.protected(manage_users)
    def getConfigurationZMIRepresentation(self):
        """ Returns a configuration representation for the ZMI """
        try:
            configuration = self.getConfiguration()
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

        # Check for encryption keys and files
        encryption_settings = configuration.get('encryption_keypairs', [])
        for enc_data in encryption_settings:
            cert_file = enc_data.get('cert_file', None)
            if cert_file and not os.path.isfile(os.path.abspath(cert_file)):
                errors.append(
                  {'key': 'cert_file (encryption_keypairs)',
                   'severity': 'error',
                   'description': f'Cannot read certificate file {cert_file}'})

            key_file = enc_data.get('key_file', None)
            if key_file and not os.path.isfile(os.path.abspath(key_file)):
                errors.append(
                  {'key': 'key_file (encryption_keypairs)',
                   'severity': 'error',
                   'description': f'Cannot read private key file {key_file}'})

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

    @security.protected(manage_users)
    def manage_reloadConfiguration(self, REQUEST):
        """ ZMI helper to force-reload the configuration file """
        clearConfigurationCaches()
        self._configuration = None
        qs = 'manage_tabs_message=Configuration reloaded'
        REQUEST.RESPONSE.redirect(
            f'{self.absolute_url()}/manage_configuration?{qs}')

    @security.private
    def getConfiguration(self, key=None, reload=False):
        """ Read SAML configuration keys from the instance or from a file.

        The configuration file is expected to be a valid ``pysaml2``
        configuration file, see
        https://pysaml2.readthedocs.io/en/latest/howto/config.html.

        Stores the extracted configuration values on the instance
        for easy retrieval later.

        Args:
            key (str or None): A configuration key from the configuration file.
              If no key is provided, return the entire configuration.

        Raises ``OSError`` if the configuration file does not exist

        Raises ``ValueError`` if the configuration file is malformed

        Raises ``KeyError`` if the configuration does not contain the key
        """
        cfg_dict = self._configuration

        if cfg_dict is None or reload is True:
            cfg_dict = self._configuration = self._load_configuration_file()

        if key is None:
            return cfg_dict

        return cfg_dict[key]

    @security.private
    def getPySAML2Configuration(self):
        """ Create a pysaml2 configuration object from the internal
        configuration
        """
        cfg = getPySAML2Configuration(self._uid)

        if cfg is None:
            cfg = Config()
            try:
                cfg.load(copy.deepcopy(self.getConfiguration()))
                setPySAML2Configuration(self._uid, cfg)
                logger.debug(
                    'getPySAML2Configuration: Created pysaml2 configuration')
            except Exception as exc:
                logger.debug(
                    f'getPySAML2Configuration: Invalid configuration\n{exc}')
                return None

        return cfg

    def _load_configuration_file(self):
        """ Load a pysaml2 configuration file

        Returns:
            The dictionary named CONFIG

        Raises:
            ValueError if the file cannot be imported or the attribute
            CONFIG does not exist
        """
        mod_parent_path = self.getConfigurationFolderPath()
        cfg_path = self.getConfigurationFilePath()
        if mod_parent_path not in sys.path:
            sys.path.insert(0, mod_parent_path)

        try:
            # This intricate dance is needed to allow re-loading the module
            # at run-time
            importlib.invalidate_caches()
            mod = importlib.import_module(self.getConfigurationModuleName())
            mod = importlib.reload(mod)
            cfg = copy.deepcopy(mod.CONFIG)
        except ModuleNotFoundError:
            raise ValueError(f'Missing configuration file at {cfg_path}')
        except Exception as exc:
            raise ValueError('Malformed configuration file at '
                             f'{cfg_path}: {str(exc)}')

        # Clean up sys.path and imports
        sys.path.remove(mod_parent_path)
        del mod

        logger.debug(f'_load_configuration_file: Re-loaded {cfg_path}')

        return cfg


InitializeClass(PySAML2ConfigurationSupport)
