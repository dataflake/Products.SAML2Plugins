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
""" Tests for SAML 2.0 service provider view
"""

from .base import PluginViewsTestBase


class SAML2ServiceProviderViewTests(PluginViewsTestBase):

    def _getTargetClass(self):
        from ..serviceprovider import SAML2ServiceProviderView
        return SAML2ServiceProviderView

    def test___call__(self):
        view = self._makeOne()

        # XXX # The request doesn't carry any SAML data yet
        # XXX self.assertEqual(view(), {})

        # XXX # SAML response from https://mocksaml.com
        # XXX with open(self._test_path('samlresponse1.txt'), 'r') as fp:
        # XXX     view.request['SAMLResponse'] = fp.read()
        # XXX view.request['RelayState'] = 'http://foo'
        # XXX view.request.method = 'POST'
        # XXX self.assertIn('jenstest@example.com', str(view()))
