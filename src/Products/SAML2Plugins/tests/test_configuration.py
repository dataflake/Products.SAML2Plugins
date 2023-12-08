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

from .base import TEST_CONFIG_FOLDER
from .base import PluginTestBase


class PySAML2ConfigurationTests(PluginTestBase):

    def _getTargetClass(self):
        from ..PluginBase import SAML2PluginBase
        return SAML2PluginBase

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
        self.assertIsNone(plugin._v_configuration)

        # Set a configuration path but the file isn't there
        plugin._configuration_folder = TEST_CONFIG_FOLDER

        with self.assertRaises(OSError) as context:
            plugin.getConfiguration('service')
        error_msg = str(context.exception)
        self.assertIn('No such file or directory', error_msg)
        self.assertIn(f'{TEST_CONFIG_FOLDER}', error_msg)
        self.assertIn(plugin.getConfigurationFileName(), error_msg)
        self.assertIsNone(plugin._v_configuration)

        # Force a UID that will load an invalid configuration file
        plugin._uid = 'invalid'

        with self.assertRaises(ValueError) as context:
            plugin.getConfiguration('service')
        error_msg = str(context.exception)
        self.assertIn('Malformed configuration file', error_msg)
        self.assertIn(f'{TEST_CONFIG_FOLDER}', error_msg)
        self.assertIn(plugin.getConfigurationFileName(), error_msg)
        self.assertIn('Expecting value: line 1 column 1 (char 0)', error_msg)
        self.assertIsNone(plugin._v_configuration)

        # Force a UID that will load a valid configuration
        plugin._uid = 'test1'

        self.assertIn('sp', plugin.getConfiguration('service').keys())
        self.assertIsNotNone(plugin._v_configuration)
        self.assertEqual(plugin.getConfiguration('service'),
                         plugin._v_configuration['service'])

        # Passing None as key returns the entire configuration
        self.assertEqual(plugin.getConfiguration(), plugin._v_configuration)

    def test_getConfigurationZMIRepresentation(self):
        plugin = self._makeOne('test1')

        # No configuration folder path is set
        self.assertIn('No configuration folder path set',
                      plugin.getConfigurationZMIRepresentation())

        # Set a configuration path but the file isn't there
        plugin._configuration_folder = TEST_CONFIG_FOLDER
        error_msg = plugin.getConfigurationZMIRepresentation()
        self.assertIn('No such file or directory', error_msg)
        self.assertIn(f'{TEST_CONFIG_FOLDER}', error_msg)
        self.assertIn(plugin.getConfigurationFileName(), error_msg)

        # Force a UID that will load an invalid configuration file
        plugin._uid = 'invalid'
        error_msg = plugin.getConfigurationZMIRepresentation()
        self.assertIn('Malformed configuration file', error_msg)
        self.assertIn(f'{TEST_CONFIG_FOLDER}', error_msg)
        self.assertIn(plugin.getConfigurationFileName(), error_msg)
        self.assertIn('Expecting value: line 1 column 1 (char 0)', error_msg)

        # Force a UID that will load a valid configuration
        plugin._uid = 'test1'
        self.assertIn('sp', plugin.getConfigurationZMIRepresentation())

    def test_getConfigurationErrors(self):
        plugin = self._makeOne('test2')
        plugin._configuration_folder = TEST_CONFIG_FOLDER

        # Using the configuration at saml2plugin_test2.json
        # to start with.
        plugin._uid = 'test2'

        expected_faulty_keys = ('cert_file', 'key_file', 'xmlsec_binary',
                                'local', 'cert', 'attribute_maps',
                                'organization')
        faulty_keys = [x['key'] for x in plugin.getConfigurationErrors()]
        self.assertEqual(set(expected_faulty_keys), set(faulty_keys))

        # Repair errors one by one
        self.assertIn('key_file', faulty_keys)
        key_file = os.path.join(TEST_CONFIG_FOLDER, 'saml2plugintest.key')
        plugin._v_configuration['key_file'] = key_file
        faulty_keys = [x['key'] for x in plugin.getConfigurationErrors()]
        self.assertNotIn('key_file', faulty_keys)

        self.assertIn('cert_file', faulty_keys)
        cert_file = os.path.join(TEST_CONFIG_FOLDER, 'saml2plugintest.pem')
        plugin._v_configuration['cert_file'] = cert_file
        faulty_keys = [x['key'] for x in plugin.getConfigurationErrors()]
        self.assertNotIn('cert_file', faulty_keys)

        plugin.metadata_sign = True
        del plugin._v_configuration['cert_file']
        del plugin._v_configuration['key_file']
        faulty_keys = [x['key'] for x in plugin.getConfigurationErrors()]
        self.assertIn('cert_file', faulty_keys)
        plugin._v_configuration['key_file'] = key_file
        faulty_keys = [x['key'] for x in plugin.getConfigurationErrors()]
        self.assertIn('cert_file', faulty_keys)
        plugin._v_configuration['cert_file'] = cert_file
        faulty_keys = [x['key'] for x in plugin.getConfigurationErrors()]
        self.assertNotIn('cert_file', faulty_keys)

        self.assertIn('xmlsec_binary', faulty_keys)
        xmlsec_binary = os.path.join(TEST_CONFIG_FOLDER, 'dummy_xmlsec1')
        plugin._v_configuration['xmlsec_binary'] = xmlsec_binary
        faulty_keys = [x['key'] for x in plugin.getConfigurationErrors()]
        self.assertNotIn('xmlsec_binary', faulty_keys)

        del plugin._v_configuration['xmlsec_binary']
        faulty_keys = [x['key'] for x in plugin.getConfigurationErrors()]
        self.assertIn('xmlsec_binary', faulty_keys)
        plugin._v_configuration['xmlsec_binary'] = xmlsec_binary
        faulty_keys = [x['key'] for x in plugin.getConfigurationErrors()]
        self.assertNotIn('xmlsec_binary', faulty_keys)

        self.assertIn('local', faulty_keys)
        plugin._v_configuration['metadata']['local'] = [
            os.path.join(TEST_CONFIG_FOLDER, 'dummy_local_idp_config.xml')]
        faulty_keys = [x['key'] for x in plugin.getConfigurationErrors()]
        self.assertNotIn('local', faulty_keys)

        self.assertIn('cert', faulty_keys)
        plugin._v_configuration['metadata']['remote'][0]['cert'] = \
            os.path.join(TEST_CONFIG_FOLDER, 'saml2plugintest.pem')
        faulty_keys = [x['key'] for x in plugin.getConfigurationErrors()]
        self.assertNotIn('cert', faulty_keys)

        self.assertIn('attribute_maps', faulty_keys)
        plugin._v_configuration['attribute_maps'] = TEST_CONFIG_FOLDER
        faulty_keys = [x['key'] for x in plugin.getConfigurationErrors()]
        self.assertNotIn('attribute_maps', faulty_keys)

        self.assertIn('organization', faulty_keys)
        plugin._v_configuration['organization']['name'] = 'foo'
        faulty_keys = [x['key'] for x in plugin.getConfigurationErrors()]
        self.assertIn('organization', faulty_keys)
        plugin._v_configuration['organization']['url'] = 'http://localhost'
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
