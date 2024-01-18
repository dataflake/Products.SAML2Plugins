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
""" Tests for PySAML2 configuration support
"""

import os
from unittest.mock import MagicMock

from .base import TEST_CONFIG_FOLDER
from .base import PluginTestCase
from .dummy import DummyRequest


class PySAML2ConfigurationTests(PluginTestCase):

    def _getTargetClass(self):
        from ..PluginBase import SAML2PluginBase
        return SAML2PluginBase

    def test_getConfigurationFileName(self):
        plugin = self._makeOne('test1')
        self.assertEqual(plugin.getConfigurationFileName(),
                         f'saml2_cfg_{plugin._uid}.py')

        plugin._uid = 'test1'
        self.assertEqual(plugin.getConfigurationFileName(),
                         'saml2_cfg_test1.py')

    def test_getConfigurationFilePath(self):
        plugin = self._makeOne('test1')

        # No configuration folder is set
        self.assertIn(f'saml2_cfg_{plugin._uid}.py',
                      plugin.getConfigurationFilePath())
        self.assertNotIn(TEST_CONFIG_FOLDER, plugin.getConfigurationFilePath())

        # Set a configuration folder path
        plugin._configuration_folder = TEST_CONFIG_FOLDER
        self.assertEqual(
            plugin.getConfigurationFilePath(),
            f'{TEST_CONFIG_FOLDER}/saml2_cfg_{plugin._uid}.py')

        # Change the UID
        plugin._uid = 'test1'
        self.assertEqual(plugin.getConfigurationFilePath(),
                         f'{TEST_CONFIG_FOLDER}/saml2_cfg_test1.py')

    def test_haveConfigurationFile(self):
        plugin = self._makeOne('test1')

        # Default configuration folder is set, which does not have a file
        self.assertFalse(plugin.haveConfigurationFile())

        # Set a configuration folder path, file does not exist
        plugin._configuration_folder = TEST_CONFIG_FOLDER
        self.assertFalse(plugin.haveConfigurationFile())

        # Change the UID so a file can be found
        plugin._uid = 'test1'
        self.assertTrue(plugin.haveConfigurationFile())

    def test_getConfiguration(self):
        plugin = self._makeOne('test1')

        # Default configuration folder is set, which does not have a file
        with self.assertRaises(ValueError) as context:
            plugin.getConfiguration('service')
        self.assertIn('Missing configuration file', str(context.exception))
        self.assertIsNone(plugin._configuration)

        # Set a configuration path but the file isn't there
        plugin._configuration_folder = TEST_CONFIG_FOLDER

        with self.assertRaises(ValueError) as context:
            plugin.getConfiguration('service')
        error_msg = str(context.exception)
        self.assertIn('Missing configuration file', error_msg)
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
        self.assertIn('invalid syntax', error_msg)
        self.assertIsNone(plugin._configuration)

        # Force a UID that will load a valid configuration
        plugin._uid = 'test1'

        self.assertIn('sp', plugin.getConfiguration('service').keys())
        cfg_dict = plugin._configuration
        self.assertIsNotNone(cfg_dict)
        self.assertEqual(plugin.getConfiguration('service'),
                         cfg_dict['service'])

        # Passing None as key returns the entire configuration
        self.assertEqual(plugin.getConfiguration(), cfg_dict)

    def test_getConfigurationZMIRepresentation(self):
        plugin = self._makeOne('test1')

        # Default configuration folder is set, which does not have a file
        self.assertIn('Missing configuration file',
                      plugin.getConfigurationZMIRepresentation())

        # Set a configuration path but the file isn't there
        plugin._configuration_folder = TEST_CONFIG_FOLDER
        error_msg = plugin.getConfigurationZMIRepresentation()
        self.assertIn('Missing configuration file', error_msg)
        self.assertIn(f'{TEST_CONFIG_FOLDER}', error_msg)
        self.assertIn(plugin.getConfigurationFileName(), error_msg)

        # Force a UID that will load an invalid configuration file
        plugin._uid = 'invalid'
        error_msg = plugin.getConfigurationZMIRepresentation()
        self.assertIn('Malformed configuration file', error_msg)
        self.assertIn(f'{TEST_CONFIG_FOLDER}', error_msg)
        self.assertIn(plugin.getConfigurationFileName(), error_msg)
        self.assertIn('invalid syntax', error_msg)

        # Force a valid configuration
        self._create_valid_configuration(plugin)
        self.assertIn('sp', plugin.getConfigurationZMIRepresentation())

    def test_getPySAML2Configuration_function(self):
        # Test the module function
        from ..configuration import getPySAML2Configuration
        from ..configuration import setPySAML2Configuration

        plugin = self._makeOne('test1')
        self._create_valid_configuration(plugin)
        old_cfg = getPySAML2Configuration(plugin._uid)

        # saml2 configuration instance, the actual value is not important
        self.assertTrue(plugin.getPySAML2Configuration().entityid)

        # Force-set configuration
        setPySAML2Configuration(plugin._uid, 'something')
        self.assertEqual(plugin.getPySAML2Configuration(), 'something')

        # Cleanup
        setPySAML2Configuration(plugin._uid, old_cfg)

    def test_getPySAML2Configuration(self):
        # Test the plugin method
        plugin = self._makeOne('valid')
        plugin._configuration_folder = TEST_CONFIG_FOLDER

        # Grab a valid configuration
        plugin._uid = 'valid'
        self.assertTrue(plugin.getPySAML2Configuration())

        # invalid configuration
        plugin._configuration = None
        plugin._uid = 'test2'
        self.assertIsNone(plugin.getPySAML2Configuration())

    def test_getConfigurationErrors(self):
        plugin = self._makeOne('test2')
        plugin._configuration_folder = TEST_CONFIG_FOLDER

        # Using the configuration at saml2_cfg_test2.py
        # to start with.
        plugin._uid = 'test2'

        expected_faulty_keys = ('cert_file', 'key_file', 'xmlsec_binary',
                                'local', 'cert', 'attribute_maps',
                                'organization',
                                'key_file (encryption_keypairs)',
                                'cert_file (encryption_keypairs)')
        faulty_keys = [x['key'] for x in plugin.getConfigurationErrors()]
        self.assertEqual(set(expected_faulty_keys), set(faulty_keys))

        cfg_dict = plugin._configuration
        # Repair errors one by one
        self.assertIn('key_file', faulty_keys)
        key_file = os.path.join(TEST_CONFIG_FOLDER, 'saml2plugintest.key')
        cfg_dict['key_file'] = key_file
        plugin._configuration = cfg_dict
        faulty_keys = [x['key'] for x in plugin.getConfigurationErrors()]
        self.assertNotIn('key_file', faulty_keys)

        self.assertIn('cert_file', faulty_keys)
        cert_file = os.path.join(TEST_CONFIG_FOLDER, 'saml2plugintest.pem')
        cfg_dict['cert_file'] = cert_file
        plugin._configuration = cfg_dict
        faulty_keys = [x['key'] for x in plugin.getConfigurationErrors()]
        self.assertNotIn('cert_file', faulty_keys)

        plugin.metadata_sign = True
        del cfg_dict['cert_file']
        del cfg_dict['key_file']
        plugin._configuration = cfg_dict
        faulty_keys = [x['key'] for x in plugin.getConfigurationErrors()]
        self.assertIn('cert_file', faulty_keys)
        cfg_dict['key_file'] = key_file
        plugin._configuration = cfg_dict
        faulty_keys = [x['key'] for x in plugin.getConfigurationErrors()]
        self.assertIn('cert_file', faulty_keys)
        cfg_dict['cert_file'] = cert_file
        plugin._configuration = cfg_dict
        faulty_keys = [x['key'] for x in plugin.getConfigurationErrors()]
        self.assertNotIn('cert_file', faulty_keys)

        self.assertIn('key_file (encryption_keypairs)', faulty_keys)
        key_file = os.path.join(TEST_CONFIG_FOLDER, 'saml2plugintest.key')
        cfg_dict['encryption_keypairs'][0]['key_file'] = key_file
        plugin._configuration = cfg_dict
        faulty_keys = [x['key'] for x in plugin.getConfigurationErrors()]
        self.assertNotIn('key_file (encryption_keypairs)', faulty_keys)

        self.assertIn('cert_file (encryption_keypairs)', faulty_keys)
        cert_file = os.path.join(TEST_CONFIG_FOLDER, 'saml2plugintest.pem')
        cfg_dict['encryption_keypairs'][0]['cert_file'] = cert_file
        plugin._configuration = cfg_dict
        faulty_keys = [x['key'] for x in plugin.getConfigurationErrors()]
        self.assertNotIn('cert_file (encryption_keypairs)', faulty_keys)

        self.assertIn('xmlsec_binary', faulty_keys)
        xmlsec_binary = os.path.join(TEST_CONFIG_FOLDER, 'dummy_xmlsec1')
        cfg_dict['xmlsec_binary'] = xmlsec_binary
        plugin._configuration = cfg_dict
        faulty_keys = [x['key'] for x in plugin.getConfigurationErrors()]
        self.assertNotIn('xmlsec_binary', faulty_keys)

        del cfg_dict['xmlsec_binary']
        plugin._configuration = cfg_dict
        faulty_keys = [x['key'] for x in plugin.getConfigurationErrors()]
        self.assertIn('xmlsec_binary', faulty_keys)
        cfg_dict['xmlsec_binary'] = xmlsec_binary
        plugin._configuration = cfg_dict
        faulty_keys = [x['key'] for x in plugin.getConfigurationErrors()]
        self.assertNotIn('xmlsec_binary', faulty_keys)

        self.assertIn('local', faulty_keys)
        cfg_dict['metadata']['local'] = [
            os.path.join(TEST_CONFIG_FOLDER, 'dummy_local_idp_config.xml')]
        plugin._configuration = cfg_dict
        faulty_keys = [x['key'] for x in plugin.getConfigurationErrors()]
        self.assertNotIn('local', faulty_keys)

        self.assertIn('cert', faulty_keys)
        cfg_dict['metadata']['remote'][0]['cert'] = \
            os.path.join(TEST_CONFIG_FOLDER, 'saml2plugintest.pem')
        plugin._configuration = cfg_dict
        faulty_keys = [x['key'] for x in plugin.getConfigurationErrors()]
        self.assertNotIn('cert', faulty_keys)

        self.assertIn('attribute_maps', faulty_keys)
        cfg_dict['attribute_maps'] = TEST_CONFIG_FOLDER
        plugin._configuration = cfg_dict
        faulty_keys = [x['key'] for x in plugin.getConfigurationErrors()]
        self.assertNotIn('attribute_maps', faulty_keys)

        self.assertIn('organization', faulty_keys)
        cfg_dict['organization']['name'] = 'foo'
        plugin._configuration = cfg_dict
        faulty_keys = [x['key'] for x in plugin.getConfigurationErrors()]
        self.assertIn('organization', faulty_keys)
        cfg_dict['organization']['url'] = 'http://localhost'
        plugin._configuration = cfg_dict
        faulty_keys = [x['key'] for x in plugin.getConfigurationErrors()]
        self.assertNotIn('organization', faulty_keys)

        # Exceptions loading the configuration don't propagate
        def error_out():
            raise ValueError('BAD')
        plugin.getConfiguration = error_out
        self.assertEqual(plugin.getConfigurationErrors(),
                         [{'key': '-',
                           'severity': 'fatal',
                           'description': 'Cannot load configuration: BAD'}])

    def test_manage_reloadConfig(self):
        plugin = self._makeOne('test1')
        self._create_valid_configuration(plugin)

        self.assertTrue(plugin._configuration)
        plugin.manage_reloadConfiguration(DummyRequest())
        self.assertFalse(plugin._configuration)

    def test_getAttributeMaps(self):
        plugin = self._makeOne('test1')
        self._create_valid_configuration(plugin)

        # There isn't much to test other than the fact that something
        # gets returned.
        attr_maps = plugin.getAttributeMaps()
        self.assertIsInstance(attr_maps, tuple)
        self.assertTrue(attr_maps)

        # Make sure configuration failures don't propagate
        plugin.getPySAML2Configuration = MagicMock(return_value=None)
        self.assertEqual(plugin.getAttributeMaps(), ())
