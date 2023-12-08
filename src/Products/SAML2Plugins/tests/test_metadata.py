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
""" Tests for SAML 2.0 metadata generation
"""

import os
import subprocess

from .base import TEST_CONFIG_FOLDER
from .base import PluginTestBase


class SAML2MetadataTests(PluginTestBase):
    # Metadata generation is handled by PySAML2 itself, so there's
    # not much that makes sense to test.

    def _getTargetClass(self):
        from ..PluginBase import SAML2PluginBase
        return SAML2PluginBase

    def _test_path(self, filename):
        return os.path.join(TEST_CONFIG_FOLDER, filename)

    def _create_valid_configuration(self, plugin):
        cfg = plugin._v_configuration
        # Massage a configuration so it becomes valid
        results = subprocess.run(['which', 'xmlsec1'], capture_output=True)
        if results.returncode:
            self.fail('To run this test "xmlsec1" must be on the $PATH')
        cfg['xmlsec_binary'] = results.stdout.strip().decode()
        cfg['key_file'] = self._test_path('saml2plugintest.key')
        cfg['cert_file'] = self._test_path('saml2plugintest.pem')

    def test_generateMetadata(self):
        plugin = self._makeOne('test1')
        plugin._configuration_folder = TEST_CONFIG_FOLDER

        # Using the configuration at saml2plugin_valid.json
        # to start with.
        plugin._uid = 'valid'
        plugin.getConfiguration()  # Generate the internal configuration

        # Massage the configuration to make it valid
        self._create_valid_configuration(plugin)

        # Just seeing that this does not fail
        xml_string = plugin.generateMetadata()
        self.assertIsInstance(xml_string, str)

    def test_getMetadataZMIRepresentation(self):
        plugin = self._makeOne('test1')
        plugin._configuration_folder = TEST_CONFIG_FOLDER

        # Using the configuration at saml2plugin_valid.json
        # to start with.
        plugin._uid = 'valid'
        plugin.getConfiguration()  # Generate the internal configuration

        # Without massaging the configuration the method will return an error
        self.assertIn('Error creating metadata representiation:',
                      plugin.getMetadataZMIRepresentation())

        # Massage the configuration to make it valid
        self._create_valid_configuration(plugin)

        # Just seeing that this does not fail
        xml_string = plugin.getMetadataZMIRepresentation()
        self.assertIsInstance(xml_string, str)
