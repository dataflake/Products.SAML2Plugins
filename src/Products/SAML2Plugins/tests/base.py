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

import unittest


class PluginTestBase(unittest.TestCase):

    def _makeOne(self):
        return self._getTargetClass()('testplugin')

    def _getTargetClass(self):
        raise NotImplemented('Must be implemented in derived classes')


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
