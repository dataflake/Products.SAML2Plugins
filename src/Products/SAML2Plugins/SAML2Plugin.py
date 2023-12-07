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
""" SAML 2.0 plugin class for the PluggableAuthService
"""

from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from zope.interface import implementer

from .interfaces import ISAML2Plugin
from .PluginBase import SAML2PluginBase


manage_addSAML2PluginForm = PageTemplateFile(
    'www/SAML2Plugin_add', globals(),
    __name__='manage_addSAML2PluginForm')


@implementer(ISAML2Plugin)
class SAML2Plugin(SAML2PluginBase):
    """ SAML 2.0 plugin class for the PluggableAuthService """

    meta_type = 'SAML 2.0 Plugin'
    zmi_icon = 'fas fa-address-book'


def manage_addSAML2Plugin(self, id, title, REQUEST=None):
    """ Factory method to instantiate a SAML2Plugin """
    # Make sure we really are working in our container (the
    # PluggableAuthService object)
    self = self.this()

    self._setObject(id, SAML2Plugin(id, title=title))

    if REQUEST is not None:
        REQUEST.RESPONSE.redirect(f'{self.absolute_url()}/manage_main')
