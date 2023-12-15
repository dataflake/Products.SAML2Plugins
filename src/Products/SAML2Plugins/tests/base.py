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

from ..configuration import clearAllCaches
from ..configuration import getConfigurationDict
from ..configuration import setConfigurationDict


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
