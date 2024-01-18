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
""" Browser view for the SAML 2.0 single logout functionality
"""

import logging

from Products.Five import BrowserView


logger = logging.getLogger('Products.SAML2Plugins')


class SAML2SingleLogoutView(BrowserView):
    """ Single logout service browser view """

    def __call__(self):
        """ Interact with request from the SAML 2.0 Identity Provider (IdP) """
        saml_response = self.request.get('SAMLResponse', '')
        binding = 'REDIRECT'
        result = 'Logged out'

        if self.request.method == 'POST':
            binding = 'POST'

        try:
            logout_path = self.context.handleSLORequest(saml_response, binding)
        except Exception:
            result = 'Logout failed'
            logout_path = ''

        # Clear local credentials
        self.context.resetCredentials(self.request, self.request.RESPONSE)

        if logout_path:
            logger.debug(f'SLO view: Success, redirecting to {logout_path}')
            self.request.response.redirect(logout_path, lock=1)
        else:
            return result
