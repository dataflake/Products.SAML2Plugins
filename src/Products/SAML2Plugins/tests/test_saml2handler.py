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
""" Tests for the SAML 2.0 handler
"""

from saml2.cache import Cache
from saml2.client import Saml2Client

from .base import TEST_CONFIG_FOLDER
from .base import PluginTestBase


class SAML2HandlerTests(PluginTestBase):

    def _getTargetClass(self):
        from ..PluginBase import SAML2PluginBase
        return SAML2PluginBase

    def _makeOne(self):
        # For these tests we always want a correctly configured plugin
        plugin = self._getTargetClass()('test')
        plugin._configuration_folder = TEST_CONFIG_FOLDER
        plugin._uid = 'valid'
        plugin.getConfiguration()
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

    def test_handleSAML2Auth(self):
        plugin = self._makeOne()

        # Empty SAML reponse
        self.assertEqual(plugin.handleSAML2Auth(''), {})

        # SAML response from https://mocksaml.com
        with open(self._test_path('samlresponse1.txt'), 'r') as fp:
            saml_response = fp.read()
        result = plugin.handleSAML2Auth(saml_response, binding='POST')
        self.assertIn('jenstest@example.com', str(result))
