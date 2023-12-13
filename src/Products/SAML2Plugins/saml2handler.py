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

from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_HTTP_REDIRECT
from saml2.cache import Cache
from saml2.client import Saml2Client

from AccessControl import ClassSecurityInfo
from AccessControl.class_init import InitializeClass


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
    def handleSAML2Auth(self, saml_response, relay_state='', binding='POST'):
        """ Handle an incoming SAML 2.0 authentication response """
        session_info = {}
        saml2_client = self.getPySAML2Client()
        if binding == 'POST':
            saml_binding = BINDING_HTTP_POST
        else:
            saml_binding = BINDING_HTTP_REDIRECT

        saml_resp = saml2_client.parse_authn_request_response(
                        saml_response, saml_binding)
        if saml_resp is not None:
            session_info = saml_resp.session_info()
            print(session_info)

        return 'Success'


InitializeClass(SAML2Handler)
