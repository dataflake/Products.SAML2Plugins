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
""" Browser view for the plugin Service Provider (SP) functionality
"""

from Products.Five import BrowserView


class SAML2ServiceProviderView(BrowserView):
    """ Service Provider browser view """

    def __call__(self):
        """ Interact with request from the SAML 2.0 Identity Provider (IdP) """
        saml_response = self.request.get('SAMLResponse', '')
        saml_relay_state = self.request.get('RelayState', '')
        binding = ''

        if self.request.method == 'POST':
            # IdP used bindings protocol HTTP-POST
            binding = 'POST'
        else:
            # IdP used bindings protocol HTTP-Redirect, which is rare
            # because a signed IdP response may exceed URL size limits
            # The value was deflated, base64-encoded and url-quoted by the IdP,
            # see https://en.wikipedia.org/wiki/SAML_2.0#HTTP_Redirect_Binding
            binding = 'REDIRECT'

        user_info = self.context.handleSAML2Response(saml_response,
                                                     saml_relay_state,
                                                     binding)
        if user_info:
            self.request.SESSION.set(self.context._uid, user_info)
            return 'Success'

        return 'Failure'
