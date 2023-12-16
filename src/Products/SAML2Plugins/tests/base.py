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
""" Base classes for SAML2 plugin test classes
"""

import os
import subprocess
import unittest
import urllib
from unittest.mock import MagicMock

from ..configuration import clearAllCaches
from ..configuration import getConfigurationDict
from ..configuration import setConfigurationDict
from .dummy import DummyNameId
from .dummy import DummyRequest
from .dummy import DummyUser


here = os.path.dirname(os.path.abspath(__file__))
TEST_CONFIG_FOLDER = os.path.join(here, 'test_data')


class PluginTestCase(unittest.TestCase):

    def setUp(self):
        super().setUp()
        clearAllCaches()

    def _makeOne(self, *args, **kw):
        configuration_folder = kw.pop('configuration_folder', None)
        plugin = self._getTargetClass()(*args, **kw)
        if configuration_folder is not None:
            plugin._configuration_folder = configuration_folder
        return plugin

    def _getTargetClass(self):
        raise NotImplementedError('Must be implemented in derived classes')

    def _test_path(self, filename):
        return os.path.join(TEST_CONFIG_FOLDER, filename)

    def _create_valid_configuration(self, plugin):
        plugin._configuration_folder = TEST_CONFIG_FOLDER
        plugin._uid = 'valid'
        cfg = plugin.getConfiguration()
        # Massage a configuration so it becomes valid
        results = subprocess.run(['which', 'xmlsec1'], capture_output=True)
        if results.returncode:
            self.fail('To run this test "xmlsec1" must be on the $PATH')
        cfg['xmlsec_binary'] = results.stdout.strip().decode()
        cfg['key_file'] = self._test_path('saml2plugintest.key')
        cfg['cert_file'] = self._test_path('saml2plugintest.pem')
        cfg['metadata'] = {}
        cfg['metadata']['local'] = [self._test_path('mocksaml_metadata.xml')]
        # This should only be used for testing
        cfg['service']['sp']['allow_unsolicited'] = True
        setConfigurationDict(plugin._uid, cfg)


class InterfaceTestMixin:

    def test_interfaces(self):
        from zope.interface.verify import verifyClass

        from Products.PluggableAuthService.interfaces.plugins import \
            IAuthenticationPlugin
        from Products.PluggableAuthService.interfaces.plugins import \
            IChallengePlugin
        from Products.PluggableAuthService.interfaces.plugins import \
            ICredentialsResetPlugin
        from Products.PluggableAuthService.interfaces.plugins import \
            IExtractionPlugin
        from Products.PluggableAuthService.interfaces.plugins import \
            IPropertiesPlugin

        verifyClass(IAuthenticationPlugin, self._getTargetClass())
        verifyClass(IChallengePlugin, self._getTargetClass())
        verifyClass(ICredentialsResetPlugin, self._getTargetClass())
        verifyClass(IExtractionPlugin, self._getTargetClass())
        verifyClass(IPropertiesPlugin, self._getTargetClass())


class SAML2PluginBaseTests:

    def test_instantiation_defaults(self):
        plugin = self._makeOne('test1')
        self.assertEqual(plugin.getId(), 'test1')
        self.assertEqual(plugin.title, '')
        self.assertEqual(plugin.login_attribute, 'login')
        self.assertEqual(plugin.metadata_valid, 2)
        self.assertFalse(plugin.metadata_sign)
        self.assertFalse(plugin.metadata_envelope)
        self.assertIn('etc', plugin.getConfigurationFolderPath())
        self.assertIsNone(getConfigurationDict(plugin._uid))
        self.assertIsInstance(plugin._uid, str)
        self.assertTrue(plugin._uid)

    def test_instantiation(self):
        plugin = self._makeOne('test1', title='This is a test',
                               configuration_folder=TEST_CONFIG_FOLDER)
        self.assertEqual(plugin.getId(), 'test1')
        self.assertEqual(plugin.title, 'This is a test')
        self.assertEqual(plugin.getConfigurationFolderPath(),
                         TEST_CONFIG_FOLDER)
        self.assertIsNone(getConfigurationDict(plugin._uid))
        self.assertIsInstance(plugin._uid, str)
        self.assertTrue(plugin._uid)

    def test_authenticateCredentials(self):
        plugin = self._makeOne('test1')

        # Plugin UID not in credentials
        creds = {'login': 'testuser'}
        self.assertIsNone(plugin.authenticateCredentials(creds))

        # Bad plugin uid in credentials
        creds = {'login': 'testuser', 'plugin_uid': 'bad'}
        self.assertIsNone(plugin.authenticateCredentials(creds))

        # Correct UID but no login information
        creds = {'plugin_uid': plugin._uid}
        self.assertIsNone(plugin.authenticateCredentials(creds))

        # Correct UID
        creds = {'login': 'testuser', 'plugin_uid': plugin._uid}
        self.assertEqual(plugin.authenticateCredentials(creds),
                         ('testuser', 'testuser'))

    def test_challenge(self):
        plugin = self._makeOne('test1')
        self._create_valid_configuration(plugin)
        req = DummyRequest()
        response = req.RESPONSE

        # Empty request
        self.assertTrue(plugin.challenge(req, response))
        self.assertTrue(response.locked)
        self.assertIn('SAMLRequest=', response.redirected)
        self.assertNotIn('RelayState', response.redirected)

        # Set a return URL
        return_url = 'https://foo'
        req.set('ACTUAL_URL', return_url)
        self.assertTrue(plugin.challenge(req, response))
        self.assertTrue(response.locked)
        self.assertIn('SAMLRequest=', response.redirected)
        self.assertIn(f'RelayState={urllib.parse.quote(return_url)}',
                      response.redirected)

        # Set a return URL and a query string
        query_string = 'came_from=/foo/bar'
        full_url = f'{return_url}?{query_string}'
        req.set('QUERY_STRING', query_string)
        self.assertTrue(plugin.challenge(req, response))
        self.assertTrue(response.locked)
        self.assertIn('SAMLRequest=', response.redirected)
        self.assertIn(f'RelayState={urllib.parse.quote(full_url)}',
                      response.redirected)

    def test_resetCredentials(self):
        plugin = self._makeOne('test1')
        self._create_valid_configuration(plugin)
        req = DummyRequest()
        session = req.SESSION

        # No session info
        self.assertFalse(session.get(plugin._uid))
        plugin.resetCredentials(req, req.RESPONSE)
        self.assertFalse(session.get(plugin._uid))

        # Add session info to delete
        self.assertFalse(session.get(plugin._uid))
        session[plugin._uid] = {'name_id': DummyNameId('foo')}
        self.assertTrue(session.get(plugin._uid))
        plugin.resetCredentials(req, req.RESPONSE)
        self.assertFalse(session.get(plugin._uid))

        # act like the user was logged in
        plugin.logoutLocally = MagicMock(return_value=True)
        session[plugin._uid] = {'name_id': DummyNameId('foo')}
        self.assertTrue(session.get(plugin._uid))
        plugin.resetCredentials(req, req.RESPONSE)
        self.assertFalse(session.get(plugin._uid))

    def test_extractCredentials(self):
        plugin = self._makeOne('test1')
        self._create_valid_configuration(plugin)
        req = DummyRequest()
        session = req.SESSION

        # No session data yet
        self.assertEqual(plugin.extractCredentials(req),
                         {'plugin_uid': plugin._uid})

        # Add some session data
        req.set('REMOTE_ADDR', '0.0.0.0')
        req.set('REMOTE_HOST', 'somehost')
        session[plugin._uid] = {'name_id': DummyNameId('foo'),
                                plugin.login_attribute: 'testuser1',
                                'issuer': 'https://samltest'}
        self.assertEqual(plugin.extractCredentials(req),
                         {'plugin_uid': plugin._uid,
                          'login': 'testuser1',
                          'password': '',
                          'remote_host': 'somehost',
                          'remote_address': '0.0.0.0'})

    def test_getPropertiesForUser(self):
        plugin = self._makeOne('test1')
        self._create_valid_configuration(plugin)
        req = DummyRequest()
        session = req.SESSION
        user = DummyUser('testuser')

        # Empty session
        self.assertEqual(plugin.getPropertiesForUser(user, req), {})

        # session data exists, but not for the user in question
        session.set(plugin._uid, {plugin.login_attribute: 'someoneelse'})
        self.assertEqual(plugin.getPropertiesForUser(user, req), {})

        # Correct session data
        session.set(plugin._uid,
                    {plugin.login_attribute: 'testuser',
                     'someproperty': 'foo'})
        self.assertEqual(plugin.getPropertiesForUser(user, req),
                         {plugin.login_attribute: 'testuser',
                          'someproperty': 'foo'})
