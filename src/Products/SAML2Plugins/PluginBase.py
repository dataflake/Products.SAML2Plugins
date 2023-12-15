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

import copy
import uuid
from urllib.parse import quote

from AccessControl import ClassSecurityInfo
from AccessControl.class_init import InitializeClass
from AccessControl.Permissions import manage_users
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
from .saml2handler import SAML2Handler


class SAML2PluginBase(BasePlugin,
                      PySAML2ConfigurationSupport,
                      SAML2MetadataProvider,
                      SAML2Handler):
    """ SAML 2.0 base plugin class """

    security = ClassSecurityInfo()
    login_attribute = 'login'
    metadata_valid = 2
    metadata_sign = False
    metadata_envelope = False

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

    _properties = (({'id': 'login_attribute',
                     'label': 'Login attribute (required)',
                     'type': 'string',
                     'mode': 'w'},
                    {'id': 'metadata_valid',
                     'label': 'Metadata validity (hours)',
                     'type': 'int',
                     'mode': 'w'},
                    {'id': 'metadata_sign',
                     'label': 'Sign metadata',
                     'type': 'boolean',
                     'mode': 'w'},
                    {'id': 'metadata_envelope',
                     'label': 'Use enclosing metadata EntitiesDescriptor',
                     'type': 'boolean',
                     'mode': 'w'},)
                   + BasePlugin._properties)

    def __init__(self, id, title=''):
        """ Initialize a new instance """
        self.id = id
        self.title = title
        self._configuration_folder = None

        # Set a unique UID as key for the configuration file
        # so that each plugin in the ZODB can have a unique configuration
        self._uid = f'{id}_{str(uuid.uuid4())}'

    #
    #   IAuthenticationPlugin implementation
    #
    @security.private
    def authenticateCredentials(self, credentials):
        """ See IAuthenticationPlugin.

        Args:
            credentials (dict): A mapping of user information returned by
                an ILoginPasswordExtractionPlugin extractCredentials call

        Returns:
            A tuple consisting of user ID and login.
        """
        if credentials.get(self._uid, None) is None:
            # The passed-in credentials did not come from this plugin, fail
            return None

        if credentials.get('login', None) is None:
            # User is not logged in or login expired
            return None

        # The credentials were already checked for expiration in the preceding
        # extractCredentials step so we accept it immediately.
        return (credentials['login'], credentials['login'])

    #
    # IChallengePlugin implementation
    #
    @security.private
    def challenge(self, request, response, **kw):
        """ See IChallengePlugin.

        Challenge the user for credentials.
        """
        came_from_url = request.get('ACTUAL_URL')
        qs = request.get('QUERY_STRING')
        if qs:
            came_from_url = f'{came_from_url}?{qs}'
        url = (f'{self.getAuthenticationRedirect()}'
               f'&RelayState={quote(came_from_url)}')

        response.redirect(url, lock=1)

        return True

    #
    # ICredentialsResetPlugin implementation
    #
    @security.private
    def resetCredentials(self, request, response):
        """ See ICredentialsResetPlugin.

        Clear out user credentials locally.

        Args:
            request (Zope request): The incoming Zope request instance

            response (Zope response): The response instance from the request
        """
        session_info = request.SESSION.get(self._uid, None)
        if session_info and self.isLoggedIn(session_info['name_id']):
            self.logoutLocally(session_info['name_id'])
        request.SESSION.set(self._uid, {})

    #
    # IExtractionPlugin implementation
    #
    @security.private
    def extractCredentials(self, request):
        """ See IExtractionPlugin.

        Extract credentials from 'request'. This is using user data in the Zope
        session and checks back with the SAML library to make sure the user is
        not expired.

        Args:
            request (Zope request): The incoming Zope request instance

        Returns:
            A mapping with the plugin UID and, if an unexpired user session
            exists, information about the user.
        """
        creds = {'plugin_uid': self._uid}
        session_info = request.SESSION.get(self._uid, None)
        if session_info and self.isLoggedIn(session_info['name_id']):
            creds['login'] = session_info[self.login_attribute]
            creds['password'] = ''
            creds['remote_host'] = session_info['issuer']
            creds['remote_address'] = request.get('REMOTE_ADDR', '')

        return creds

    #
    # IPropertiesPlugin implementation
    #
    @security.private
    def getPropertiesForUser(self, user, request=None):
        """ See IPropertiesPlugin.

        Get properties for the user.
        """
        properties = {}
        session_info = request.SESSION.get(self._uid, None)

        if session_info and user.getId() == session_info[self.login_attribute]:
            properties = copy.deepcopy(session_info)

        return properties


InitializeClass(SAML2PluginBase)

classImplements(SAML2PluginBase,
                IAuthenticationPlugin,
                IChallengePlugin,
                ICredentialsResetPlugin,
                IExtractionPlugin,
                IPropertiesPlugin,
                )
