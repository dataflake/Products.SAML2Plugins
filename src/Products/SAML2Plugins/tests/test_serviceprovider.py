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
""" Tests for the SAML 2.0 service provider
"""

from unittest.mock import MagicMock

from saml2.cache import Cache
from saml2.client import Saml2Client

from .base import PluginTestCase
from .dummy import DummyNameId
from .dummy import DummyPySAML2Client


class SAML2ServiceProviderTests(PluginTestCase):

    def _getTargetClass(self):
        from ..PluginBase import SAML2PluginBase
        return SAML2PluginBase

    def _makeOne(self):
        # For these tests we always want a correctly configured plugin
        plugin = self._getTargetClass()('test')
        self._create_valid_configuration(plugin)
        return plugin

    def test_getPySAML2Cache(self):
        plugin = self._makeOne()
        self.assertIsInstance(plugin.getPySAML2Cache(), Cache)

    def test_getPySAML2Client(self):
        plugin = self._makeOne()
        saml2_client = plugin.getPySAML2Client()
        self.assertIsInstance(saml2_client, Saml2Client)

        # The first call generates the client object, subsequent calls
        # will return it from cache, so the objects should be identical
        self.assertTrue(saml2_client is plugin.getPySAML2Client())

    def test_isLoggedIn(self):
        plugin = self._makeOne()
        name_id = DummyNameId('testid')
        dummy_client = DummyPySAML2Client()

        # User is not logged in
        self.assertFalse(plugin.isLoggedIn(name_id))

        # Mock out a logged in user
        plugin.getPySAML2Client = MagicMock(return_value=dummy_client)
        dummy_client._store_name_id(name_id)
        self.assertTrue(plugin.isLoggedIn(name_id))

    def test_logoutLocally(self):
        plugin = self._makeOne()
        name_id = DummyNameId('testid')
        dummy_client = DummyPySAML2Client()

        # User is not logged in, call doesn't raise errors
        self.assertIsNone(plugin.logoutLocally(name_id))

        # Mock out a logged in user
        plugin.getPySAML2Client = MagicMock(return_value=dummy_client)
        dummy_client._store_name_id(name_id)
        self.assertIsNone(plugin.logoutLocally(name_id))

    def test_handleACSRequest(self):
        plugin = self._makeOne()

        # Empty SAML response
        self.assertEqual(plugin.handleACSRequest(''), {})

        # XXX There should be more tests here
