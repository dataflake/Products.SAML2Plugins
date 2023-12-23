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
            logger.error(f'Parsing SAML response failed:\n{exc}')
            return user_info

        if saml_resp is not None:
            # Available data:
            # saml_resp.get_identity(): map of user attributes
            # saml_resp.get_subject(): NameID instance for user id
            # saml_resp.ava: contains result of saml_resp.get_identity()
            # saml_resp.session_info(): user attributes plus session info
            name_id_object = saml_resp.get_subject()
            user_info['name_id'] = str(name_id_object)
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
                'handleACSRequest: Got data for {user_info["_login"]}')
        else:
            logger.debug('handleACSRequest: Invalid SamlResponse, no user')

        return user_info


InitializeClass(SAML2ServiceProvider)
