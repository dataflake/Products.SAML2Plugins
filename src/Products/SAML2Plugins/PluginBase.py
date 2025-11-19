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
import logging
import time
import urllib
import uuid

from AccessControl import ClassSecurityInfo
from AccessControl.class_init import InitializeClass
from AccessControl.Permissions import manage_users
from AccessControl.SecurityManagement import getSecurityManager
from Products.PageTemplates.PageTemplateFile import PageTemplateFile

from Products.PluggableAuthService.interfaces.plugins import \
    IAuthenticationPlugin
from Products.PluggableAuthService.interfaces.plugins import IChallengePlugin
from Products.PluggableAuthService.interfaces.plugins import \
    ICredentialsResetPlugin
from Products.PluggableAuthService.interfaces.plugins import IExtractionPlugin
from Products.PluggableAuthService.interfaces.plugins import IPropertiesPlugin
from Products.PluggableAuthService.interfaces.plugins import IRolesPlugin
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Products.PluggableAuthService.utils import classImplements

from .configuration import PySAML2ConfigurationSupport
from .metadata import SAML2MetadataProvider
from .serviceprovider import SAML2ServiceProvider


logger = logging.getLogger('Products.SAML2Plugins')


class SAML2PluginBase(BasePlugin,
                      PySAML2ConfigurationSupport,
                      SAML2MetadataProvider,
                      SAML2ServiceProvider):
    """ SAML 2.0 base plugin class """

    security = ClassSecurityInfo()
    default_idp = None
    login_attribute = ''
    assign_roles = []
    inactivity_timeout = 2
    logout_path = ''
    metadata_sign = False
    metadata_envelope = False
    protocol = 'http'  # The PAS challenge 'protocol' we use.

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

    _properties = (({'id': '_uid',
                     'label': 'Plugin unique ID (read-only)',
                     'type': 'string',
                     'mode': 'r'},
                    {'id': 'title',
                     'label': 'Title (optional)',
                     'type': 'string',
                     'mode': 'w'},
                    {'id': 'default_idp',
                     'label': 'Default Identity Provider',
                     'type': 'selection',
                     'select_variable': 'getIdentityProviders',
                     'mode': 'w'},
                    {'id': 'login_attribute',
                     'label': 'Login attribute (SAML subject if empty)',
                     'type': 'string',
                     'mode': 'w'},
                    {'id': 'inactivity_timeout',
                     'label': 'Session inactivity timeout (hours)',
                     'type': 'int',
                     'mode': 'w'},
                    {'id': 'assign_roles',
                     'label': 'Roles for SAML-authenticated users',
                     'type': 'multiple selection',
                     'select_variable': 'getCandidateRoles',
                     'mode': 'w'},
                    {'id': 'logout_path',
                     'label': 'Logout redirect path',
                     'type': 'string',
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

    def __setstate__(self, state):
        # This is called when the instance is loaded from the ZODB, for example
        # when the instance is accessed first after restarting Zope.
        # Re-setting the SAML configuration dictionary on the instance to make
        # sure a Zope restart causes re-reading the configuration from disk.
        super().__setstate__(state)
        self._configuration = None

    #
    #   ZMI helpers
    #
    @security.protected(manage_users)
    def getCandidateRoles(self):
        """ Get roles that can be assigned to users

        Filters out special role names that should not be assigned.

        Returns:
            A tuple of role names
        """
        roles = sorted(self.valid_roles())
        for special_role in ('Anonymous', 'Authenticated', 'Owner'):
            if special_role in roles:
                roles.remove(special_role)
        return tuple(roles)

    @security.protected(manage_users)
    def getIdentityProviders(self):
        """ Get a list of IdentityProvider EntityId strings """
        cfg = self.getPySAML2Configuration()
        metadata = getattr(cfg, 'metadata', None)
        if metadata is not None:
            return tuple(sorted(metadata.keys()))

        return ()

    @security.public
    def loggedInHere(self, REQUEST):
        """ Helper to signal if the authenticated user is from this plugin

        Returns: True or False
        """
        user = getSecurityManager().getUser()
        session_info = REQUEST.SESSION.get(self._uid)
        return session_info and user.getId() == session_info.get('_login', ())

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
        if credentials.get('plugin_uid', None) != self._uid:
            # The passed-in credentials did not come from this plugin, fail
            return None

        if credentials.get('login', None) is None:
            # User is not logged in or login expired
            logger.debug('authenticateCredentials: No login session active')
            return None

        # The credentials were already checked for expiration in the preceding
        # extractCredentials step so we accept it immediately.
        logger.debug(
            f'authenticateCredentials: Authenticated {credentials["login"]}')
        return (credentials['login'], credentials['login'])

    #
    # IChallengePlugin implementation
    #
    @security.private
    def challenge(self, request, response, **kw):
        """ See IChallengePlugin.

        Challenge the user for credentials.
        """
        self.idpCommunicate(self.getIdPAuthenticationData(request), response)
        return True

    @security.public
    def login(self, REQUEST):
        """ Trigger a manual login challenge

        This publicly available method can be used to manually trigger a
        login challenge and pass along information about the preferred
        identity provider to use.

        Raises ValueError if an identity provider choice is passed in that is
        not part of the configuration.
        """
        saml_req_info = None
        idp_entityid = urllib.parse.unquote(REQUEST.get('idp', ''))

        if idp_entityid:
            if idp_entityid in self.getIdentityProviders():
                logger.debug(f'login: Using IdP {idp_entityid}')
                saml_req_info = self.getIdPAuthenticationData(
                    REQUEST, idp_entityid=idp_entityid)
            else:
                msg = f'login: Invalid identity provider {idp_entityid}'
                logger.error(msg)
                raise ValueError(msg)
        else:
            logger.debug('login: Using default IdP')
            saml_req_info = self.getIdPAuthenticationData(REQUEST)

        return self.idpCommunicate(saml_req_info, REQUEST.RESPONSE)

    #
    # ICredentialsResetPlugin implementation
    #
    @security.private
    def resetCredentials(self, request, response):
        """ See ICredentialsResetPlugin.

        Clear out user credentials locally. This logout process does not log
        the user out of the Identity Provider. It just clears local session
        information and pysaml2 caches.

        Args:
            request (Zope request): The incoming Zope request instance

            response (Zope response): The response instance from the request
        """
        session_info = request.SESSION.get(self._uid, None)
        if session_info:
            login = session_info.get('_login', 'n/a')
            logger.debug(f'resetCredentials: Logging out {login}')
            self.logoutLocally(session_info['name_id'])
        else:
            logger.debug('resetCredentials: No login session active')
        request.SESSION.set(self._uid, {})

    #
    # IExtractionPlugin implementation
    #
    @security.private
    def extractCredentials(self, request):
        """ See IExtractionPlugin.

        Extract credentials from 'request'. This is using user data in the Zope
        session.

        Args:
            request (Zope request): The incoming Zope request instance

        Returns:
            A mapping with the plugin UID and, if an unexpired user session
            exists, information about the user.
        """
        creds = {'plugin_uid': self._uid}
        session_info = request.SESSION.get(self._uid, None)
        if session_info:
            # Don't accept sessions older than the activity timeout
            now_secs = int(time.time())
            max_inactive = now_secs - (self.inactivity_timeout * 3600)
            if session_info.get('last_active', 0) < max_inactive:
                return creds
            else:
                session_info['last_active'] = now_secs
                request.SESSION.set(self._uid, session_info)

            creds['login'] = session_info['_login']
            creds['password'] = ''
            creds['remote_host'] = request.get('REMOTE_HOST', '')
            creds['remote_address'] = request.get('REMOTE_ADDR', '')
            logger.debug(f'extractCredentials: Extracted {creds["login"]}')
        else:
            logger.debug('extractCredentials: No login session active')

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

        if session_info and user.getId() == session_info['_login']:
            properties = copy.deepcopy(session_info)
            logger.debug(
                'getPropertiesForUser: Found data for '
                f'{session_info["_login"]}')
        else:
            logger.debug('getPropertiesForUser: No login session active')

        return properties

    #
    # IRolesPlugin implementation
    #
    @security.private
    def getRolesForPrincipal(self, principal, request=None):
        """ See IRoles.

        Get roles for the principal (a group or a user).
        """
        roles = []
        session_info = request.SESSION.get(self._uid, None)

        if session_info and \
           principal.getId() == session_info['_login']:
            roles = self.assign_roles
            logger.debug('getRolesForPrincipal: Found roles for '
                         f'{principal.getId()}')
        else:
            logger.debug('getRolesForPrincipal: No login session active')

        return tuple(sorted(roles))


InitializeClass(SAML2PluginBase)

classImplements(SAML2PluginBase,
                IAuthenticationPlugin,
                IChallengePlugin,
                ICredentialsResetPlugin,
                IExtractionPlugin,
                IPropertiesPlugin,
                IRolesPlugin,
                )
