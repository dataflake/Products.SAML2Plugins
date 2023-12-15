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

from ...SAML2Plugin import SAML2Plugin
from ...tests.base import PluginTestCase
from ...tests.dummy import DummyRequest


class PluginViewsTestBase(PluginTestCase):

    def _makeOne(self):
        plugin = SAML2Plugin('test')
        self._create_valid_configuration(plugin)
        return self._getTargetClass()(plugin, DummyRequest())
