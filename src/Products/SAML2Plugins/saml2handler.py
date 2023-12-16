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
""" SAML interaction handler for SAML 2.0 protocol requests
"""

import logging

from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_HTTP_REDIRECT
from saml2.cache import Cache
from saml2.client import Saml2Client

from AccessControl import ClassSecurityInfo
from AccessControl.class_init import InitializeClass


logger = logging.getLogger('Products.SAML2Plugins')
CACHES = {}


class SAML2Handler:

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
    def isLoggedIn(self, name_id_instance):
        """ Is the user in the PySAML2 cache?

        Args:
            name_id_instance (saml2.saml.NameID): The NameID instance
                corresponding to the user

        Returns:
            True or False
        """
        client = self.getPySAML2Client()
        return client.is_logged_in(name_id_instance)

    @security.private
    def logoutLocally(self, name_id_instance):
        """ Remove a user from the PySAML2 cache

        Args:
            name_id_instance (saml2.saml.NameID): The NameID instance
                corresponding to the user
        """
        client = self.getPySAML2Client()
        if client.is_logged_in(name_id_instance):
            client.local_logout(name_id_instance)

    @security.private
    def getAuthenticationRedirect(self):
        """ Prepare a SAML 2.0 authentication request

        Returns:
            A URL with query string for HTTP-Redirect
        """
        client = self.getPySAML2Client()
        req_id, info = client.prepare_for_authenticate()
        headers = dict(info['headers'])
        return headers['Location']

    @security.private
    def handleACSRequest(self, saml_response, binding='POST'):
        """ Handle incoming SAML 2.0 assertions """
        user_info = {}
        saml2_client = self.getPySAML2Client()

        if binding == 'POST':
            saml_binding = BINDING_HTTP_POST
        else:
            saml_binding = BINDING_HTTP_REDIRECT

        saml_resp = saml2_client.parse_authn_request_response(
                        saml_response, saml_binding)

        if saml_resp is not None:
            # Available data:
            # saml_resp.get_identity(): map of user attributes
            # saml_resp.get_subject(): NameID instance for user id
            # saml_resp.ava: contains result of saml_resp.get_identity()
            # saml_resp.session_info(): user attributes plus session info
            user_info['name_id'] = str(saml_resp.get_subject())
            user_info['issuer'] = saml_resp.issuer()

            for key, value in saml_resp.get_identity().items():
                if isinstance(value, (list, tuple)):
                    value = value[0]
                user_info[key] = value

                # For convenience store login under a fixed key
                if key == self.login_attribute:
                    user_info['_login'] = value

            if not user_info.get('_login'):
                user_info['_login'] = f'({self.login_attribute} not in data)'
            logger.debug(
                f'handleACSRequest: Got data for {user_info["_login"]}')
        else:
            logger.debug('handleACSRequest: Invalid SamlResponse, no user')

        return user_info


InitializeClass(SAML2Handler)
