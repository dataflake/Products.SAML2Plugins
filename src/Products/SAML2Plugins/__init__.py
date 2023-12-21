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
""" SAML2Plugins product initialization
"""

from AccessControl.Permissions import add_user_folders

from Products.PluggableAuthService.PluggableAuthService import \
    registerMultiPlugin

from .monkeypatch import applyPatches
from .SAML2Plugin import SAML2Plugin
from .SAML2Plugin import manage_addSAML2Plugin
from .SAML2Plugin import manage_addSAML2PluginForm


applyPatches()
registerMultiPlugin(SAML2Plugin.meta_type)


def initialize(context):
    """ Register the SAML 2.0 plugin classes with Zope
    """

    context.registerClass(SAML2Plugin,
                          permission=add_user_folders,
                          constructors=(manage_addSAML2PluginForm,
                                        manage_addSAML2Plugin),
                          visibility=None)
