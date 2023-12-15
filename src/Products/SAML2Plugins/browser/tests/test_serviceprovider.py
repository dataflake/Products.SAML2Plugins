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

from unittest.mock import MagicMock

from .base import PluginViewsTestBase


class SAML2ServiceProviderViewTests(PluginViewsTestBase):

    def _getTargetClass(self):
        from ..serviceprovider import SAML2ServiceProviderView
        return SAML2ServiceProviderView

    def test___call__POST(self):
        view = self._makeOne()
        view.request.method = 'POST'
        req = view.request
        plugin = view.context

        # The request doesn't carry any SAML data yet
        self.assertEqual(view(), 'Failure')
        self.assertFalse(req.SESSION.get(plugin._uid))

        # Mocking out a successful SAML interaction result
        user_info = {'foo': 'bar'}
        view.context.handleSAML2Response = MagicMock(return_value=user_info)
        self.assertEqual(view(), 'Success')
        self.assertEqual(req.SESSION[plugin._uid], user_info)

    def test___call__REDIRECT(self):
        view = self._makeOne()
        view.request.method = 'GET'
        req = view.request
        plugin = view.context

        # The request doesn't carry any SAML data yet
        self.assertEqual(view(), 'Failure')
        self.assertFalse(req.SESSION.get(plugin._uid))

        # Mocking out a successful SAML interaction result
        user_info = {'foo': 'bar'}
        view.context.handleSAML2Response = MagicMock(return_value=user_info)
        self.assertEqual(view(), 'Success')
        self.assertEqual(req.SESSION[plugin._uid], user_info)
