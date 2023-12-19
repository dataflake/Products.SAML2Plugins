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
""" Tests for SAML 2.0 metadata view
"""

from .base import PluginViewsTestBase


class SAML2MetadataViewTests(PluginViewsTestBase):

    def _getTargetClass(self):
        from ..metadata import SAML2MetadataView
        return SAML2MetadataView

    def test___call__(self):
        view = self._makeOne()
        result = view()

        self.assertTrue(result.startswith(
                            '<?xml version="1.0" ?>\n<ns0:EntityDescriptor'))
