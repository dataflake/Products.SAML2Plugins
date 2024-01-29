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
import time
import unittest
import urllib
from unittest.mock import MagicMock

from AccessControl.SecurityManagement import newSecurityManager
from AccessControl.SecurityManagement import noSecurityManager

from ..configuration import clearConfigurationCaches
from .dummy import DummyNameId
from .dummy import DummyRequest
from .dummy import DummyUser


here = os.path.dirname(os.path.abspath(__file__))
TEST_CONFIG_FOLDER = os.path.join(here, 'test_data')


class PluginTestCase(unittest.TestCase):

    def setUp(self):
        super().setUp()
        clearConfigurationCaches()

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
        plugin._configuration = cfg


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
        from Products.PluggableAuthService.interfaces.plugins import \
            IRolesPlugin

        verifyClass(IAuthenticationPlugin, self._getTargetClass())
        verifyClass(IChallengePlugin, self._getTargetClass())
        verifyClass(ICredentialsResetPlugin, self._getTargetClass())
        verifyClass(IExtractionPlugin, self._getTargetClass())
        verifyClass(IPropertiesPlugin, self._getTargetClass())
        verifyClass(IRolesPlugin, self._getTargetClass())


class SAML2PluginBaseTests:

    def test_instantiation_defaults(self):
        plugin = self._makeOne('test1')
        self.assertEqual(plugin.getId(), 'test1')
        self.assertEqual(plugin.title, '')
        self.assertEqual(plugin.default_idp, None)
        self.assertEqual(plugin.login_attribute, '')
        self.assertFalse(plugin.metadata_sign)
        self.assertFalse(plugin.metadata_envelope)
        self.assertIn('etc', plugin.getConfigurationFolderPath())
        self.assertIsNone(plugin._configuration)
        self.assertIsInstance(plugin._uid, str)
        self.assertTrue(plugin._uid)

    def test_instantiation(self):
        plugin = self._makeOne('test1', title='This is a test',
                               configuration_folder=TEST_CONFIG_FOLDER)
        self.assertEqual(plugin.getId(), 'test1')
        self.assertEqual(plugin.title, 'This is a test')
        self.assertEqual(plugin.getConfigurationFolderPath(),
                         TEST_CONFIG_FOLDER)
        self.assertIsNone(plugin._configuration)
        self.assertIsInstance(plugin._uid, str)
        self.assertTrue(plugin._uid)

    def test___setstate__(self):
        plugin = self._makeOne('test1')
        self._create_valid_configuration(plugin)

        self.assertIsNotNone(plugin._configuration)
        plugin.__setstate__(plugin.__dict__)
        self.assertIsNone(plugin._configuration)

    def test_getIdentityProviders(self):
        plugin = self._makeOne('test1')
        self._create_valid_configuration(plugin)

        self.assertEqual(plugin.getIdentityProviders(),
                         ('https://saml.example.com/entityid',))

        # Don't blow up if no identity provider metadata exists
        cfg = plugin.getConfiguration()
        del cfg['metadata']
        clearConfigurationCaches()
        plugin._configuration = cfg
        self.assertEqual(plugin.getIdentityProviders(), ())

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

    def test_challenge_binding_redirect(self):
        plugin = self._makeOne('test1')
        self._create_valid_configuration(plugin)
        req = DummyRequest()
        response = req.RESPONSE

        # Empty request
        self.assertTrue(plugin.challenge(req, response))
        self.assertTrue(response.locked)
        self.assertEqual(response.status, 303)
        self.assertIn('SAMLRequest=', response.redirected)
        self.assertNotIn('RelayState', response.redirected)

        # Set a return URL
        return_url = 'https://foo'
        req.set('ACTUAL_URL', return_url)
        self.assertTrue(plugin.challenge(req, response))
        self.assertTrue(response.locked)
        self.assertEqual(response.status, 303)
        self.assertIn('SAMLRequest=', response.redirected)
        self.assertIn(f'RelayState={urllib.parse.quote(return_url, safe="")}',
                      response.redirected)

        # Set a return URL and a query string
        query_string = 'came_from=/foo/bar'
        full_url = f'{return_url}?{query_string}'
        req.set('QUERY_STRING', query_string)
        self.assertTrue(plugin.challenge(req, response))
        self.assertTrue(response.locked)
        self.assertEqual(response.status, 303)
        self.assertIn('SAMLRequest=', response.redirected)
        self.assertIn(f'RelayState={urllib.parse.quote(full_url, safe="")}',
                      response.redirected)

    def test_challenge_binding_post(self):
        plugin = self._makeOne('test1')
        self._create_valid_configuration(plugin)
        post_idp_cfg = self._test_path('mocksaml_metadata_binding_post.xml')
        plugin._configuration['metadata']['local'] = [post_idp_cfg]
        req = DummyRequest()
        response = req.RESPONSE

        # Empty request
        self.assertTrue(plugin.challenge(req, response))
        self.assertFalse(response.locked)
        self.assertFalse(response.status)
        self.assertIn('<input type="hidden" name="SAMLRequest"', response.body)
        self.assertNotIn('<input type="hidden" name="RelayState"',
                         response.body)

        # Set a return URL
        return_url = 'https://foo'
        req.set('ACTUAL_URL', return_url)
        self.assertTrue(plugin.challenge(req, response))
        self.assertFalse(response.locked)
        self.assertFalse(response.status)
        self.assertIn('<input type="hidden" name="SAMLRequest"', response.body)
        self.assertIn(
            f'<input type="hidden" name="RelayState" value="{return_url}"/>',
            response.body)

        # Set a return URL and a query string
        query_string = 'came_from=/foo/bar'
        full_url = f'{return_url}?{query_string}'
        req.set('QUERY_STRING', query_string)
        self.assertTrue(plugin.challenge(req, response))
        self.assertFalse(response.locked)
        self.assertFalse(response.status)
        self.assertIn('<input type="hidden" name="SAMLRequest"', response.body)
        self.assertIn(
            f'<input type="hidden" name="RelayState" value="{full_url}"/>',
            response.body)

    def test_login_binding_redirect(self):
        plugin = self._makeOne('test1')
        self._create_valid_configuration(plugin)
        req = DummyRequest()
        response = req.RESPONSE

        # Empty request
        plugin.login(req)
        self.assertTrue(response.locked)
        self.assertEqual(response.status, 303)
        self.assertIn('SAMLRequest=', response.redirected)
        self.assertNotIn('RelayState', response.redirected)

        # Set a return URL
        return_url = 'https://foo'
        req.set('ACTUAL_URL', return_url)
        plugin.login(req)
        self.assertTrue(response.locked)
        self.assertEqual(response.status, 303)
        self.assertIn('SAMLRequest=', response.redirected)
        self.assertIn(f'RelayState={urllib.parse.quote(return_url, safe="")}',
                      response.redirected)

        # Set a return URL and a query string
        query_string = 'came_from=/foo/bar'
        full_url = f'{return_url}?{query_string}'
        req.set('QUERY_STRING', query_string)
        plugin.login(req)
        self.assertTrue(response.locked)
        self.assertEqual(response.status, 303)
        self.assertIn('SAMLRequest=', response.redirected)
        self.assertIn(f'RelayState={urllib.parse.quote(full_url, safe="")}',
                      response.redirected)

        # Set an invalid identity provider, will raise an exception
        req.set('idp', urllib.parse.quote('https://invalid'))
        with self.assertRaises(ValueError) as context:
            plugin.login(req)
        self.assertEqual(str(context.exception),
                         'login: Invalid identity provider https://invalid')

        # Set a valid IdP
        idp = plugin.getIdentityProviders()[0]
        req.set('idp', urllib.parse.quote(idp))
        plugin.login(req)
        self.assertTrue(response.locked)
        self.assertEqual(response.status, 303)
        self.assertIn('SAMLRequest=', response.redirected)
        self.assertIn(f'RelayState={urllib.parse.quote(full_url, safe="")}',
                      response.redirected)

    def test_login_binding_post(self):
        plugin = self._makeOne('test1')
        self._create_valid_configuration(plugin)
        post_idp_cfg = self._test_path('mocksaml_metadata_binding_post.xml')
        plugin._configuration['metadata']['local'] = [post_idp_cfg]
        req = DummyRequest()
        response = req.RESPONSE

        # Empty request
        plugin.login(req)
        self.assertFalse(response.locked)
        self.assertFalse(response.status)
        self.assertIn('<input type="hidden" name="SAMLRequest"', response.body)
        self.assertNotIn('<input type="hidden" name="RelayState"',
                         response.body)

        # Set a return URL
        return_url = 'https://foo'
        req.set('ACTUAL_URL', return_url)
        plugin.login(req)
        self.assertFalse(response.locked)
        self.assertFalse(response.status)
        self.assertIn('<input type="hidden" name="SAMLRequest"', response.body)
        self.assertIn(
            f'<input type="hidden" name="RelayState" value="{return_url}"/>',
            response.body)

        # Set a return URL and a query string
        query_string = 'came_from=/foo/bar'
        full_url = f'{return_url}?{query_string}'
        req.set('QUERY_STRING', query_string)
        plugin.login(req)
        self.assertFalse(response.locked)
        self.assertFalse(response.status)
        self.assertIn('<input type="hidden" name="SAMLRequest"', response.body)
        self.assertIn(
            f'<input type="hidden" name="RelayState" value="{full_url}"/>',
            response.body)

        # Set an invalid identity provider, will raise an exception
        req.set('idp', urllib.parse.quote('https://invalid'))
        with self.assertRaises(ValueError) as context:
            plugin.login(req)
        self.assertEqual(str(context.exception),
                         'login: Invalid identity provider https://invalid')

        # Set a valid IdP
        idp = plugin.getIdentityProviders()[0]
        req.set('idp', urllib.parse.quote(idp))
        plugin.login(req)
        self.assertFalse(response.locked)
        self.assertFalse(response.status)
        self.assertIn('<input type="hidden" name="SAMLRequest"', response.body)
        self.assertIn(
            f'<input type="hidden" name="RelayState" value="{full_url}"/>',
            response.body)

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

        # Add some session data, but no last activity indicator
        req.set('REMOTE_ADDR', '0.0.0.0')
        req.set('REMOTE_HOST', 'somehost')
        session[plugin._uid] = {'name_id': DummyNameId('foo'),
                                '_login': 'testuser1',
                                'issuer': 'https://samltest'}
        self.assertEqual(plugin.extractCredentials(req),
                         {'plugin_uid': plugin._uid})

        # Add a last activity indicator, but it's too old
        max_age = int(time.time()) - (plugin.inactivity_timeout*3600)
        session[plugin._uid]['last_active'] = (max_age-1)
        self.assertEqual(plugin.extractCredentials(req),
                         {'plugin_uid': plugin._uid})

        # Set last activity indicator to an acceptable value
        session[plugin._uid]['last_active'] = (max_age+10)
        self.assertEqual(plugin.extractCredentials(req),
                         {'plugin_uid': plugin._uid,
                          'login': 'testuser1',
                          'password': '',
                          'remote_host': 'somehost',
                          'remote_address': '0.0.0.0'})
        # The last activity indicator gets updated as well
        self.assertAlmostEqual(req.SESSION[plugin._uid]['last_active'],
                               int(time.time()),
                               delta=5)

    def test_getPropertiesForUser(self):
        plugin = self._makeOne('test1')
        self._create_valid_configuration(plugin)
        req = DummyRequest()
        session = req.SESSION
        user = DummyUser('testuser')

        # Empty session
        self.assertEqual(plugin.getPropertiesForUser(user, req), {})

        # session data exists, but not for the user in question
        session.set(plugin._uid, {'_login': 'someoneelse'})
        self.assertEqual(plugin.getPropertiesForUser(user, req), {})

        # Correct session data
        session.set(plugin._uid,
                    {'_login': 'testuser',
                     'someproperty': 'foo'})
        self.assertEqual(plugin.getPropertiesForUser(user, req),
                         {'_login': 'testuser',
                          'someproperty': 'foo'})

    def test_getCandidateRoles(self):
        plugin = self._makeOne('test1')
        self._create_valid_configuration(plugin)

        # No known roles
        plugin.valid_roles = MagicMock(return_value=())
        self.assertEqual(plugin.getCandidateRoles(), ())

        # The standard set of roles in Zope
        roles = ('Anonymous', 'Authenticated', 'Manager', 'Owner')
        plugin.valid_roles = MagicMock(return_value=roles)
        self.assertEqual(plugin.getCandidateRoles(), ('Manager',))

        # Add some custom roles
        roles = ('Anonymous', 'Authenticated', 'Manager', 'Owner',
                 'arole', 'test2', 'foorole')
        plugin.valid_roles = MagicMock(return_value=roles)
        self.assertEqual(plugin.getCandidateRoles(),
                         ('Manager', 'arole', 'foorole', 'test2'))

    def test_getRolesForPrincipal(self):
        plugin = self._makeOne('test1')
        self._create_valid_configuration(plugin)
        req = DummyRequest()
        session = req.SESSION
        user = DummyUser('testuser')

        # Empty session
        self.assertEqual(plugin.getRolesForPrincipal(user, req), ())

        # session data exists, but not for the user in question
        session.set(plugin._uid, {'_login': 'someoneelse'})
        self.assertEqual(plugin.getRolesForPrincipal(user, req), ())

        # Correct session data
        session.set(plugin._uid, {'_login': 'testuser'})

        # There are no roles to assign set on the plugin yet
        self.assertEqual(plugin.getRolesForPrincipal(user, req), ())

        # Set roles to assign
        plugin.assign_roles = ['role1', 'role2']
        self.assertEqual(plugin.getRolesForPrincipal(user, req),
                         ('role1', 'role2'))

    def test_loggedInHere(self):
        plugin = self._makeOne('test1')
        self._create_valid_configuration(plugin)
        req = DummyRequest()
        session = req.SESSION
        user = DummyUser('testuser')

        # Empty session and no logged-in user
        self.assertFalse(plugin.loggedInHere(req))

        # User logged in, but session empty
        newSecurityManager(None, DummyUser('testuser'))
        self.assertFalse(plugin.loggedInHere(req))

        # User logged in but session does not match
        session.set(plugin._uid, {'_login': 'anotheruser'})
        self.assertFalse(plugin.loggedInHere(req))

        # Put the correct user into the session to make it work
        session.set(plugin._uid, {'_login': user.getId()})
        self.assertTrue(plugin.loggedInHere(req))

        # Cleanup
        noSecurityManager()
