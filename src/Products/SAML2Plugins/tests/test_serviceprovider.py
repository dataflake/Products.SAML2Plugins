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

import time
import urllib
from unittest.mock import MagicMock

from saml2.cache import Cache
from saml2.client import Saml2Client

from .base import PluginTestCase
from .dummy import DummyNameId
from .dummy import DummyPySAML2Client
from .dummy import DummyRequest
from .dummy import DummySAMLResponse


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

    def test_getIdPAuthenticationData_binding_redirect(self):
        plugin = self._makeOne()
        req = DummyRequest()

        # Empty request
        http_info = plugin.getIdPAuthenticationData(req)
        headers = dict(http_info['headers'])
        redirect = headers['Location']
        self.assertIn('SAMLRequest=', redirect)
        self.assertNotIn('RelayState', redirect)

        # Set an explicit URL with came_from
        return_url = 'https://foo/bar'
        req.set('came_from', return_url)
        http_info = plugin.getIdPAuthenticationData(req)
        headers = dict(http_info['headers'])
        redirect = headers['Location']
        self.assertIn('SAMLRequest=', redirect)
        self.assertIn(f'RelayState={urllib.parse.quote(return_url, safe="")}',
                      redirect)
        req.set('came_from', '')

        # Set an implicit return URL
        return_url = 'https://foo'
        req.set('ACTUAL_URL', return_url)
        http_info = plugin.getIdPAuthenticationData(req)
        headers = dict(http_info['headers'])
        redirect = headers['Location']
        self.assertIn('SAMLRequest=', redirect)
        self.assertIn(f'RelayState={urllib.parse.quote(return_url, safe="")}',
                      redirect)

        # Set a return URL and a query string
        query_string = 'info=/foo/bar'
        full_url = f'{return_url}?{query_string}'
        req.set('QUERY_STRING', query_string)
        http_info = plugin.getIdPAuthenticationData(req)
        headers = dict(http_info['headers'])
        redirect = headers['Location']
        self.assertIn('SAMLRequest=', redirect)
        self.assertIn(f'RelayState={urllib.parse.quote(full_url, safe="")}',
                      redirect)

        # Pass an unknown IdP EntityId
        with self.assertRaises(Exception) as context:
            plugin.getIdPAuthenticationData(
                        req, idp_entityid='https://foo.com/idp')
        self.assertIn('No supported bindings available for authentication',
                      str(context.exception))

    def test_getIdPAuthenticationData_binding_post(self):
        plugin = self._makeOne()
        post_idp_cfg = self._test_path('mocksaml_metadata_binding_post.xml')
        plugin._configuration['metadata']['local'] = [post_idp_cfg]
        req = DummyRequest()

        # Empty request
        http_info = plugin.getIdPAuthenticationData(req)
        headers = dict(http_info['headers'])
        body = http_info['data']
        self.assertNotIn('Location', headers)
        self.assertIn('<input type="hidden" name="SAMLRequest"', body)
        self.assertNotIn('<input type="hidden" name="RelayState"', body)

        # Set an explicit URL with came_from
        return_url = 'https://foo/bar'
        req.set('came_from', return_url)
        http_info = plugin.getIdPAuthenticationData(req)
        headers = dict(http_info['headers'])
        body = http_info['data']
        self.assertNotIn('Location', headers)
        self.assertIn('<input type="hidden" name="SAMLRequest"', body)
        self.assertIn(
            f'<input type="hidden" name="RelayState" value="{return_url}"/>',
            body)
        req.set('came_from', '')

        # Set an implicit return URL
        return_url = 'https://foo'
        req.set('ACTUAL_URL', return_url)
        http_info = plugin.getIdPAuthenticationData(req)
        headers = dict(http_info['headers'])
        body = http_info['data']
        self.assertNotIn('Location', headers)
        self.assertIn('<input type="hidden" name="SAMLRequest"', body)
        self.assertIn(
            f'<input type="hidden" name="RelayState" value="{return_url}"/>',
            body)

        # Set a return URL and a query string
        query_string = 'info=/foo/bar'
        full_url = f'{return_url}?{query_string}'
        req.set('QUERY_STRING', query_string)
        http_info = plugin.getIdPAuthenticationData(req)
        headers = dict(http_info['headers'])
        body = http_info['data']
        self.assertNotIn('Location', headers)
        self.assertIn('<input type="hidden" name="SAMLRequest"', body)
        self.assertIn(
            f'<input type="hidden" name="RelayState" value="{full_url}"/>',
            body)

        # Pass an unknown IdP EntityId
        with self.assertRaises(Exception) as context:
            plugin.getIdPAuthenticationData(
                        req, idp_entityid='https://foo.com/idp')
        self.assertIn('No supported bindings available for authentication',
                      str(context.exception))

    def test_handleACSRequest(self):
        plugin = self._makeOne()

        # Empty SAML response
        self.assertEqual(plugin.handleACSRequest(''), {})

        # Provide some sensible data
        name_id = DummyNameId('JohnDoe')
        user_data = {'key1': ['value1'], 'key2': [], 'key3': 'foo'}
        saml_response = DummySAMLResponse(subject=name_id,
                                          issuer='https://example.com/idp',
                                          identity=user_data)
        dummy_client = DummyPySAML2Client(parse_result=saml_response)
        plugin.getPySAML2Client = MagicMock(return_value=dummy_client)

        # No login attribute set yet, name_id is used
        user_info = plugin.handleACSRequest(saml_response)
        self.assertEqual(user_info['name_id'], str(name_id))
        self.assertEqual(user_info['issuer'], 'https://example.com/idp')
        self.assertEqual(user_info['_login'], name_id.text)
        self.assertEqual(user_info['key1'], 'value1')
        self.assertEqual(user_info['key2'], '')
        self.assertEqual(user_info['key3'], 'foo')
        self.assertAlmostEqual(user_info['last_active'], int(time.time()), 1)

        # Set an unknown login attribute
        plugin.login_attribute = 'unknown'
        user_info = plugin.handleACSRequest(saml_response)
        self.assertNotIn('_login', user_info)

        # Set a known login attribute
        plugin.login_attribute = 'key1'
        user_info = plugin.handleACSRequest(saml_response)
        self.assertEqual(user_info['_login'], 'value1')

        # Act like the PySAML2 response processing blew up
        # The exception should not bubble up
        failing_client = DummyPySAML2Client(parse_result='raise_error')
        plugin.getPySAML2Client = MagicMock(return_value=failing_client)
        self.assertEqual(plugin.handleACSRequest(saml_response), {})
