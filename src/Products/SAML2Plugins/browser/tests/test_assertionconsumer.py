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
""" Tests for SAML 2.0 assertion consumer view
"""

from unittest.mock import MagicMock

from .base import PluginViewsTestBase


class SAML2AssertionConsumerViewTests(PluginViewsTestBase):

    def _getTargetClass(self):
        from ..assertionconsumer import SAML2AssertionConsumerView
        return SAML2AssertionConsumerView

    def _call_test(self, request_method):
        view = self._makeOne()
        view.request.method = request_method
        req = view.request
        plugin = view.context

        # The request doesn't carry any SAML data yet
        self.assertEqual(view(), 'Failure')
        self.assertFalse(req.SESSION.get(plugin._uid))
        self.assertFalse(req.response.redirected)

        # Mocking out a successful SAML interaction result
        # but omit RelayState for a return url
        req.SESSION.clear()
        user_info = {'foo': 'bar'}
        view.context.handleACSRequest = MagicMock(return_value=user_info)
        self.assertEqual(view(), 'Success')
        self.assertEqual(req.SESSION[plugin._uid], user_info)
        self.assertEqual(req.response.redirected, '/')

        # Add relay state for an empty URL
        req.SESSION.clear()
        req.set('RelayState', '')
        self.assertEqual(view(), 'Success')
        self.assertEqual(req.SESSION[plugin._uid], user_info)
        self.assertEqual(req.response.redirected, '')

        # Add relay state for an invalid outside target
        req.SESSION.clear()
        req.set('RelayState', 'http://foo.com/target.html?key=val')
        self.assertEqual(view(), 'Success')
        self.assertEqual(req.SESSION[plugin._uid], user_info)
        self.assertEqual(req.response.redirected, '/target.html?key=val')

        # Add relay state for a valid  target
        req.SESSION.clear()
        req.set('RelayState', '/good/target.html?key=val')
        self.assertEqual(view(), 'Success')
        self.assertEqual(req.SESSION[plugin._uid], user_info)
        self.assertEqual(req.response.redirected, '/good/target.html?key=val')

    def test___call__POST(self):
        self._call_test(request_method='POST')

    def test___call__REDIRECT(self):
        self._call_test(request_method='GET')
