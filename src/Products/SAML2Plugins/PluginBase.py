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

from .configuration import PySAML2ConfigurationSupport
from .metadata import SAML2MetadataProvider


class SAML2PluginBase(BasePlugin,
                      PySAML2ConfigurationSupport,
                      SAML2MetadataProvider):
    """ SAML 2.0 base plugin class """

    security = ClassSecurityInfo()
    metadata_valid = 2
    metadata_sign = False

    security.declareProtected(manage_users, 'manage_configuration')
    manage_configuration = PageTemplateFile(
        'www/SAML2Plugin_config', globals(),
        __name__='manage_configuration')

    security.declareProtected(manage_users, 'manage_metadata')
    manage_metadata = PageTemplateFile(
        'www/SAML2Plugin_metadata', globals(),
        __name__='manage_metadata')

    manage_options = (({'label': 'Configuration',
                        'action': 'manage_configuration'},
                       {'label': 'Metadata',
                        'action': 'manage_metadata'},)
                      + BasePlugin.manage_options)

    _properties = (({'id': 'metadata_valid',
                     'label': 'Metadata validity (hours)',
                     'type': 'int',
                     'mode': 'w'},
                    {'id': 'metadata_sign',
                     'label': 'Sign metadata',
                     'type': 'boolean',
                     'mode': 'w'},)
                   + BasePlugin._properties)

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
        self._uid = f'{id}_{str(uuid.uuid4())}'

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
