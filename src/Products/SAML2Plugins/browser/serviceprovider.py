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
        binding = 'REDIRECT'

        if self.request.method == 'POST':
            binding = 'POST'

        user_info = self.context.handleACSRequest(saml_response,
                                                  saml_relay_state,
                                                  binding)
        if user_info:
            self.request.SESSION.set(self.context._uid, user_info)
            return 'Success'

        return 'Failure'
