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
""" Tests for SAML 2.0 single logout view
"""

from unittest.mock import MagicMock

from .base import PluginViewsTestBase


class SAML2SingleLogoutViewTests(PluginViewsTestBase):

    def _getTargetClass(self):
        from ..singlelogout import SAML2SingleLogoutView
        return SAML2SingleLogoutView

    def _call_test(self, request_method):
        view = self._makeOne()
        view.request.method = request_method
        req = view.request
        plugin = view.context

        # The request doesn't carry any SAML data yet
        self.assertEqual(view(), 'Logged out')
        self.assertFalse(req.SESSION.get(plugin._uid))
        self.assertFalse(req.response.redirected)

        # Set a logout path on the plugin
        plugin.logout_path = '/logged_out'
        self.assertIsNone(view())
        self.assertEqual(req.response.redirected, '/logged_out')

        # Make sure session data is cleared
        req.SESSION.set(plugin._uid, {'_login': 'foo', 'name_id': 'bar'})
        self.assertTrue(req.SESSION.get(plugin._uid))
        self.assertIsNone(view())
        self.assertFalse(req.SESSION.get(plugin._uid))

        # Exceptions during processing should not bubble up
        req.SESSION.set(plugin._uid, {'_login': 'foo', 'name_id': 'bar'})
        plugin.handleSLORequest = MagicMock(side_effect=Exception)
        self.assertEqual(view(), 'Logout failed')
        self.assertFalse(req.SESSION.get(plugin._uid))

    def test___call__POST(self):
        self._call_test(request_method='POST')

    def test___call__REDIRECT(self):
        self._call_test(request_method='GET')
