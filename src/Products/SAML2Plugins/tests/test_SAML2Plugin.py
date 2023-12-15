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
""" SAML2Plugin unit tests
"""

from Testing.ZopeTestCase import ZopeTestCase

from .base import InterfaceTestMixin
from .base import PluginTestCase
from .base import SAML2PluginBaseTests
from .dummy import DummyRequest


class SAML2PluginTests(PluginTestCase,
                       InterfaceTestMixin,
                       SAML2PluginBaseTests):

    def _getTargetClass(self):
        from ..SAML2Plugin import SAML2Plugin
        return SAML2Plugin


class SAML2PluginFunctionalTests(ZopeTestCase):

    def test_factory(self):
        from ..SAML2Plugin import manage_addSAML2Plugin

        manage_addSAML2Plugin(self.app, 'samlplugin', 'Plugin Title')
        plugin = self.app.samlplugin

        self.assertEqual(plugin.getId(), 'samlplugin')
        self.assertEqual(plugin.title, 'Plugin Title')

        # Try with a request
        req = DummyRequest()
        manage_addSAML2Plugin(self.app, 'samlplugin2', 'Plugin Title',
                              REQUEST=req)

        self.assertEqual(req.RESPONSE.redirected, 'http://nohost/manage_main')
