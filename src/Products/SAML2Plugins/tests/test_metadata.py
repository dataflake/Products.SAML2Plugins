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

from .base import TEST_CONFIG_FOLDER
from .base import PluginTestCase


class SAML2MetadataTests(PluginTestCase):
    # Metadata generation is handled by PySAML2 itself, so there's
    # not much that makes sense to test.

    def _getTargetClass(self):
        from ..PluginBase import SAML2PluginBase
        return SAML2PluginBase

    def test_generateMetadata(self):
        plugin = self._makeOne('test1')
        self._create_valid_configuration(plugin)

        # Use an envelope
        plugin.metadata_envelope = True
        xml_string = plugin.generateMetadata()
        self.assertTrue(xml_string.startswith(
                        '<?xml version="1.0" ?>\n<ns0:EntitiesDescriptor'))

        # No envelope
        plugin.metadata_envelope = False
        xml_string = plugin.generateMetadata()
        self.assertTrue(xml_string.startswith(
                        '<?xml version="1.0" ?>\n<ns0:EntityDescriptor'))

        # No envelope and signing
        plugin.metadata_sign = True
        xml_string = plugin.generateMetadata()
        self.assertTrue(xml_string.startswith(
                        '<?xml version="1.0" ?>\n<ns0:EntityDescriptor'))
        self.assertIn('<ns1:SignatureValue>', xml_string)

    def test_getMetadataZMIRepresentation(self):
        plugin = self._makeOne('test1')
        plugin._configuration_folder = TEST_CONFIG_FOLDER

        # Using the configuration at saml2plugin_valid.py
        # to start with.
        plugin._uid = 'valid'
        plugin.getConfiguration()  # Generate the internal configuration

        # Without massaging the configuration the method will return an error
        self.assertIn('Error creating metadata XML:',
                      plugin.getMetadataZMIRepresentation())

        # Massage the configuration to make it valid
        self._create_valid_configuration(plugin)

        # Use an envelope
        plugin.metadata_envelope = True
        xml_string = plugin.getMetadataZMIRepresentation()
        self.assertIn('<ns0:EntitiesDescriptor', xml_string)

        # No envelope
        plugin.metadata_envelope = False
        xml_string = plugin.getMetadataZMIRepresentation()
        self.assertIn('<ns0:EntityDescriptor', xml_string)
