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

from ..configuration import getConfigurationDict
from .base import TEST_CONFIG_FOLDER
from .base import InterfaceTestMixin
from .base import PluginTestBase


class SAML2PluginBaseTests(PluginTestBase, InterfaceTestMixin):

    def _getTargetClass(self):
        from ..PluginBase import SAML2PluginBase
        return SAML2PluginBase

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
