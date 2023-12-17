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
""" Browser view for the SAML 2.0 assertion consumer functionality
"""

import logging
from urllib.parse import urlparse
from urllib.parse import urlunparse

from Products.Five import BrowserView


logger = logging.getLogger('Products.SAML2Plugins')


class SAML2AssertionConsumerView(BrowserView):
    """ Service Provider browser view """

    def __call__(self):
        """ Interact with request from the SAML 2.0 Identity Provider (IdP) """
        saml_response = self.request.get('SAMLResponse', '')
        target_url = self.request.get('RelayState', '/')
        binding = 'REDIRECT'

        # Make sure the login target url lands here by ripping off
        # protocol and host information. Prevents an open redirect.
        if target_url:
            parsed_url = urlparse(target_url)
            target_url = urlunparse(('', '') + parsed_url[2:])

        if self.request.method == 'POST':
            binding = 'POST'

        user_info = self.context.handleACSRequest(saml_response, binding)
        if user_info:
            logger.debug(f'SP view: Success, redirecting to {target_url}')
            self.request.SESSION.set(self.context._uid, user_info)
            self.request.response.redirect(target_url, lock=1)

            return 'Success'

        return 'Failure'
