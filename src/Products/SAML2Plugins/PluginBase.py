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
""" Base class for SAML2Plugins-based PAS plugins
"""

import json
import os
import pprint
import uuid

from AccessControl import ClassSecurityInfo
from AccessControl.class_init import InitializeClass
from AccessControl.Permissions import manage_users
from App.config import getConfiguration
from Products.PageTemplates.PageTemplateFile import PageTemplateFile

from Products.PluggableAuthService.interfaces.plugins import \
    IAuthenticationPlugin
from Products.PluggableAuthService.interfaces.plugins import IChallengePlugin
from Products.PluggableAuthService.interfaces.plugins import \
    ICredentialsResetPlugin
from Products.PluggableAuthService.interfaces.plugins import IExtractionPlugin
from Products.PluggableAuthService.interfaces.plugins import IPropertiesPlugin
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Products.PluggableAuthService.utils import classImplements


class SAML2PluginBase(BasePlugin):
    """ SAML 2.0 base plugin class """

    security = ClassSecurityInfo()
    _configuration = None

    security.declareProtected(manage_users, 'manage_configuration')
    manage_configuration = PageTemplateFile(
        'www/SAML2Plugin_config', globals(),
        __name__='manage_configuration')

    manage_options = (({'label': 'Configuration',
                        'action': 'manage_configuration'},)
                      + BasePlugin.manage_options)

    def __init__(self, id, title=''):
        """ Initialize a new instance """
        self.id = id
        self.title = title

        # The configuration folder is set in a zope.conf
        # `product-config` section
        zope_config = getConfiguration()
        product_config = getattr(zope_config, 'product_config', dict())
        my_config = product_config.get('saml2plugins', dict())
        self._configuration_folder = my_config.get('configuration_folder',
                                                   None)

        # Set a unique UID as key for the configuration file
        # so that each plugin in the ZODB can have a unique configuration
        self._uid = str(uuid.uuid4())

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
        configuration = self.getConfiguration()

        return pprint.pformat(configuration)

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
        if self._configuration is None or reload is True:
            if self.getConfigurationFolderPath() is None:
                raise ValueError('No configuration folder path set')

            self._configuration = self._load_configuration_file()

        if key is None:
            return self._configuration

        return self._configuration[key]

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

    #
    #   IAuthenticationPlugin implementation
    #
    @security.private
    def authenticateCredentials(self, credentials):
        """ See IAuthenticationPlugin.

        o We expect the credentials to be those returned by
          ILoginPasswordExtractionPlugin.
        """
        pass

    #
    # IChallengePlugin implementation
    #
    @security.private
    def challenge(self, request, response, **kw):
        """ See IChallengePlugin.

        Challenge the user for credentials.
        """
        pass

    #
    # ICredentialsResetPlugin implementation
    #
    @security.private
    def resetCredentials(self, request, response):
        """ See ICredentialsResetPlugin.

        Clear out user credentials locally.
        """
        pass

    #
    # IExtractionPlugin implementation
    #
    @security.private
    def extractCredentials(self, request):
        """ See IExtractionPlugin.

        Extract credentials from 'request'.
        """
        pass

    #
    # IPropertiesPlugin implementation
    #
    @security.private
    def getPropertiesForUser(self, user, request=None):
        """ See IPropertiesPlugin.

        Get properties for the user.
        """
        pass


InitializeClass(SAML2PluginBase)

classImplements(SAML2PluginBase,
                IAuthenticationPlugin,
                IChallengePlugin,
                ICredentialsResetPlugin,
                IExtractionPlugin,
                IPropertiesPlugin,
                )
