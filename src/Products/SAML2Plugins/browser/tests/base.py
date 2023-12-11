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
""" Test case for SAML 2.0 plugin views
"""

from Testing.makerequest import makerequest

from ...SAML2Plugin import SAML2Plugin
from ...tests.base import TEST_CONFIG_FOLDER
from ...tests.base import PluginTestBase


class PluginViewsTestBase(PluginTestBase):

    def _makeOne(self):
        plugin = makerequest(SAML2Plugin('test'))
        plugin._uid = 'valid'
        plugin._configuration_folder = TEST_CONFIG_FOLDER
        plugin.getConfiguration()
        self._create_valid_configuration(plugin)
        return self._getTargetClass()(plugin, plugin.REQUEST)
