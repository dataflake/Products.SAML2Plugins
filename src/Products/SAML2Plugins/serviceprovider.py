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
""" SAML 2.0 service provider handler
"""

import logging
import time

from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_HTTP_REDIRECT
from saml2.cache import Cache
from saml2.client import Saml2Client
from saml2.ident import code as nameid_to_str
from saml2.ident import decode as str_to_nameid

from AccessControl import ClassSecurityInfo
from AccessControl.class_init import InitializeClass


logger = logging.getLogger('Products.SAML2Plugins')
CACHES = {}


class SAML2ServiceProvider:

    security = ClassSecurityInfo()
    _v_saml2client = None
    _v_saml2cache = None

    @security.private
    def getPySAML2Cache(self):
        """ Get or create a cache for caching SAML 2.0 data """
        if self._uid not in CACHES:
            CACHES[self._uid] = Cache()
        return CACHES[self._uid]

    @security.private
    def getPySAML2Client(self):
        """ Get a SAML 2.0 client that delegates interactions to pysaml2 """
        if self._v_saml2client is None:
            self._v_saml2client = Saml2Client(
                                    config=self.getPySAML2Configuration(),
                                    identity_cache=self.getPySAML2Cache())

        return self._v_saml2client

    @security.private
    def isLoggedIn(self, name_id):
        """ Is the user in the PySAML2 cache?

        Args:
            name_id (saml2.saml.NameID or str): The NameID instance
                corresponding to the user or a string representing it.

        Returns:
            True or False
        """
        if isinstance(name_id, str):
            name_id = str_to_nameid(name_id)
        client = self.getPySAML2Client()
        return client.is_logged_in(name_id)

    @security.public
    def logout(self, REQUEST):
        """ Logout triggered manually from Zope (e.g. link)

        Args:
            REQUEST (Zope REQUEST object): Zope will provide this parameter
                automatically when invoking this method through the web.
        """
        session_info = REQUEST.SESSION.get(self._uid, None)

        if not session_info:
            logger.debug('logout: No login session active')
            return 'logout: No login session active'

        if not session_info.get('name_id', None):
            logger.debug('logout: No NameID in session')
            return 'logout: No login session active'

        login = session_info.get('_login', 'n/a')

        if not self.isLoggedIn(session_info['name_id']):
            logger.debug(f'logout: User {login} is not logged into SAML')
            saml_resp_dict = {}
        else:
            client = self.getPySAML2Client()
            logger.debug(f'logout: Logging out {login}')

            saml_resp_dict = client.global_logout(
                                str_to_nameid(session_info['name_id']),
                                reason='Manual logout')
        # The response is a dictionary where the keys are Identity Provider
        # entity IDs and the values are two-element tuples. The first element
        # is the binding type and the second element is a dictionary with
        # information about constructing a logout request to the Identity
        # Provider.
        if not saml_resp_dict:
            logger.warning(
                f'logout: No SAML logout data for {login}, '
                'logging out locally only')
            self.resetCredentials(REQUEST, REQUEST.RESPONSE)

            if self.logout_path:
                logger.debug(f'logout: Redirecting to {self.logout_path}')
                REQUEST.RESPONSE.redirect(self.logout_path, lock=1)
            else:
                return 'Logged out'
        else:
            # Assumption: Each unique login is handled by exactly
            # one Identity Provider.
            idp_entity_id = list(saml_resp_dict.keys())[0]
            binding, saml_request_info = saml_resp_dict[idp_entity_id]
            logger.debug(
                f'logout: Initiating logout at {idp_entity_id}')
            return self.idpCommunicate(saml_request_info, REQUEST.RESPONSE)

    @security.private
    def idpCommunicate(self, saml_request_info, response):
        """ Communicate with the Identity Provider

        Handles redirecting or POSTing to the identity provider
        """
        headers = dict(saml_request_info['headers'])
        if 'Location' in headers:
            logger.debug('idpCommunicate: Redirecting to Identity Provider')
            response.redirect(headers['Location'],
                              status=saml_request_info.get('status', 303),
                              lock=1)
        else:
            logger.debug('idpCommunicate: POSTing to Identity Provider')
            for key, value in headers.items():
                response.setHeader(key, value)
            response.setBody(saml_request_info['data'])
            return saml_request_info['data']

    @security.private
    def logoutLocally(self, name_id):
        """ Remove a user from the PySAML2 cache

        Args:
            name_id (saml2.saml.NameID or str): The NameID instance
                corresponding to the user or a string representing it.
        """
        if isinstance(name_id, str):
            name_id = str_to_nameid(name_id)
        client = self.getPySAML2Client()
        if client.is_logged_in(name_id):
            client.local_logout(name_id)

    @security.private
    def getDefaultIdPEntityID(self):
        """ Get the entityID for the default Identity Provider

        The configuration metadata can point to more than one Identity
        Provider, but the plugin can only work with one of them at a time.

        If you use more than one IdP make sure to set the default value in the
        ZMI Properties tab.

        Returns:
            A string for the IdP entityID or None
        """
        return self.default_idp or None

    @security.private
    def getIdPAuthenticationData(self, request, idp_entityid=None):
        """ Prepare a SAML 2.0 authentication request

        Args:
            request (REQUEST): The current Zope request object

        Kwargs:
            idp_entityid (str): The IdP entity ID to use. Defaults to the
                Identity Provider selected on the ZMI Properties tab.

        Returns:
            Data to perform an authentication request, a mapping with keys
            ``headers``, ``data`` and ``status``.
        """
        return_url = request.get('came_from', '')

        if not return_url:
            return_url = request.get('ACTUAL_URL')
            if return_url:
                qs = request.get('QUERY_STRING')
                if qs:
                    return_url = f'{return_url}?{qs}'

        if not idp_entityid:
            idp_entityid = self.getDefaultIdPEntityID()

        client = self.getPySAML2Client()
        (req_id,
         binding,
         http_info) = client.prepare_for_negotiated_authenticate(
                        entityid=idp_entityid,
                        relay_state=return_url)

        return http_info

    @security.private
    def handleACSRequest(self, saml_response, binding='POST'):
        """ Handle incoming SAML 2.0 assertions """
        user_info = {}
        client = self.getPySAML2Client()

        if binding == 'POST':
            saml_binding = BINDING_HTTP_POST
        else:
            saml_binding = BINDING_HTTP_REDIRECT

        try:
            saml_resp = client.parse_authn_request_response(saml_response,
                                                            saml_binding)
        except Exception as exc:
            logger.error(
                f'handleACSRequest: Parsing SAML response failed:\n{exc}')
            return user_info

        if saml_resp is not None:
            # Available data:
            # saml_resp.get_identity(): map of user attributes
            # saml_resp.get_subject(): NameID instance for user id
            # saml_resp.ava: contains result of saml_resp.get_identity()
            # saml_resp.session_info(): user attributes plus session info
            name_id_object = saml_resp.get_subject()
            user_info['name_id'] = nameid_to_str(name_id_object)
            user_info['issuer'] = saml_resp.issuer()

            if not self.login_attribute:
                # If no login attribute has been specified, use the token
                # sent as the subject text value.
                user_info['_login'] = name_id_object.text

            for key, value in saml_resp.get_identity().items():
                if isinstance(value, (list, tuple)):
                    if not value:
                        value = ''
                    else:
                        value = value[0]
                user_info[key] = value

                # If a login attribute has been specified, use
                # that as Zope login
                if self.login_attribute and key == self.login_attribute:
                    user_info['_login'] = value

                # Initialize session activity marker
                user_info['last_active'] = int(time.time())

            if not user_info.get('_login'):
                logger.warning(
                    'handleACSRequest: Cannot find login attribute '
                    f'{self.login_attribute}, check attribute maps '
                    'or login attribute setting on the plugin!')
                return {}

            logger.debug(
                f'handleACSRequest: Got data for {user_info["_login"]}')
        else:
            logger.debug('handleACSRequest: Invalid SamlResponse, no user')

        return user_info

    @security.private
    def handleSLORequest(self, saml_response, binding='POST'):
        """ Handle incoming SAML 2.0 logout request or response """
        client = self.getPySAML2Client()
        target_path = self.logout_path or ''

        if binding == 'POST':
            saml_binding = BINDING_HTTP_POST
        else:
            saml_binding = BINDING_HTTP_REDIRECT

        try:
            saml_resp = client.parse_logout_request_response(saml_response,
                                                             saml_binding)
        except Exception as exc:
            saml_resp = None
            logger.error(
                f'handleSLORequest: Parsing SAML response failed:\n{exc}')

        if saml_resp is not None:
            try:
                saml_resp.status_ok() and \
                    logger.debug('handleSLORequest: Remote logout success')
            except Exception as exc:
                logger.debug(f'handleSLORequest: Remote logout FAIL:\n{exc}')
        else:
            logger.debug('handleSLORequest: Failure, got no SAML response')

        return target_path


InitializeClass(SAML2ServiceProvider)
