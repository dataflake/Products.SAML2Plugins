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
""" SAML2Plugin base class unit tests
"""

import os

from .base import InterfaceTestMixin
from .base import PluginTestBase


here = os.path.dirname(os.path.abspath(__file__))
TEST_CONFIG_FOLDER = os.path.join(here, 'test_configurations')


class SAML2PluginBaseTests(PluginTestBase, InterfaceTestMixin):

    def _getTargetClass(self):
        from ..PluginBase import SAML2PluginBase
        return SAML2PluginBase

    def test_instantiation_defaults(self):
        plugin = self._makeOne('test1')
        self.assertEqual(plugin.getId(), 'test1')
        self.assertEqual(plugin.title, '')
        self.assertIsNone(plugin.getConfigurationFolderPath())
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

    def test_getConfigurationFileName(self):
        plugin = self._makeOne('test1')
        self.assertEqual(plugin.getConfigurationFileName(),
                         f'saml2plugin_{plugin._uid}.json')

        plugin._uid = 'test1'
        self.assertEqual(plugin.getConfigurationFileName(),
                         'saml2plugin_test1.json')

    def test_getConfigurationFilePath(self):
        plugin = self._makeOne('test1')

        # No configuration folder is set
        self.assertIsNone(plugin.getConfigurationFilePath())

        # Set a configuration folder path
        plugin._configuration_folder = TEST_CONFIG_FOLDER
        self.assertEqual(
            plugin.getConfigurationFilePath(),
            f'{TEST_CONFIG_FOLDER}/saml2plugin_{plugin._uid}.json')

        # Change the UID
        plugin._uid = 'test1'
        self.assertEqual(plugin.getConfigurationFilePath(),
                         f'{TEST_CONFIG_FOLDER}/saml2plugin_test1.json')

    def test_haveConfigurationFile(self):
        plugin = self._makeOne('test1')

        # No configuration folder is set
        self.assertFalse(plugin.haveConfigurationFile())

        # Set a configuration folder path, file does not exist
        plugin._configuration_folder = TEST_CONFIG_FOLDER
        self.assertFalse(plugin.haveConfigurationFile())

        # Change the UID so a file can be found
        plugin._uid = 'test1'
        self.assertTrue(plugin.haveConfigurationFile())

    def test_getConfiguration(self):
        plugin = self._makeOne('test1')

        # No configuration folder path is set
        with self.assertRaises(ValueError) as context:
            plugin.getConfiguration('service')
        self.assertEqual(str(context.exception),
                         'No configuration folder path set')
        self.assertIsNone(plugin._configuration)

        # Set a configuration path but the file isn't there
        plugin._configuration_folder = TEST_CONFIG_FOLDER

        with self.assertRaises(OSError) as context:
            plugin.getConfiguration('service')
        error_msg = str(context.exception)
        self.assertIn('No such file or directory', error_msg)
        self.assertIn(f'{TEST_CONFIG_FOLDER}', error_msg)
        self.assertIn(plugin.getConfigurationFileName(), error_msg)
        self.assertIsNone(plugin._configuration)

        # Force a UID that will load an invalid configuration file
        plugin._uid = 'invalid'

        with self.assertRaises(ValueError) as context:
            plugin.getConfiguration('service')
        error_msg = str(context.exception)
        self.assertIn('Malformed configuration file', error_msg)
        self.assertIn(f'{TEST_CONFIG_FOLDER}', error_msg)
        self.assertIn(plugin.getConfigurationFileName(), error_msg)
        self.assertIn('Expecting value: line 1 column 1 (char 0)', error_msg)
        self.assertIsNone(plugin._configuration)

        # Force a UID that will load a valid configuration
        plugin._uid = 'test1'

        self.assertIn('sp', plugin.getConfiguration('service').keys())
        self.assertIsNotNone(plugin._configuration)
        self.assertEqual(plugin.getConfiguration('service'),
                         plugin._configuration['service'])

        # Passing None as key returns the entire configuration
        self.assertEqual(plugin.getConfiguration(), plugin._configuration)

    def test_getConfigurationZMIRepresentation(self):
        plugin = self._makeOne('test1')

        # No configuration folder path is set
        with self.assertRaises(ValueError) as context:
            plugin.getConfigurationZMIRepresentation()
        self.assertEqual(str(context.exception),
                         'No configuration folder path set')

        # Set a configuration path but the file isn't there
        plugin._configuration_folder = TEST_CONFIG_FOLDER

        with self.assertRaises(OSError) as context:
            plugin.getConfigurationZMIRepresentation()
        error_msg = str(context.exception)
        self.assertIn('No such file or directory', error_msg)
        self.assertIn(f'{TEST_CONFIG_FOLDER}', error_msg)
        self.assertIn(plugin.getConfigurationFileName(), error_msg)

        # Force a UID that will load an invalid configuration file
        plugin._uid = 'invalid'

        with self.assertRaises(ValueError) as context:
            plugin.getConfigurationZMIRepresentation()
        error_msg = str(context.exception)
        self.assertIn('Malformed configuration file', error_msg)
        self.assertIn(f'{TEST_CONFIG_FOLDER}', error_msg)
        self.assertIn(plugin.getConfigurationFileName(), error_msg)
        self.assertIn('Expecting value: line 1 column 1 (char 0)', error_msg)

        # Force a UID that will load a valid configuration
        plugin._uid = 'test1'

        self.assertIn('sp', plugin.getConfigurationZMIRepresentation())
