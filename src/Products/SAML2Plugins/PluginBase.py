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
""" Base class for SAML2Plugins-based PAS plugins
"""

from AccessControl import ClassSecurityInfo
from AccessControl.class_init import InitializeClass

from Products.PluggableAuthService.interfaces.plugins import \
    IAuthenticationPlugin
from Products.PluggableAuthService.interfaces.plugins import IChallengePlugin
from Products.PluggableAuthService.interfaces.plugins import \
    ICredentialsResetPlugin
from Products.PluggableAuthService.interfaces.plugins import IExtractionPlugin
from Products.PluggableAuthService.interfaces.plugins import IPropertiesPlugin
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Products.PluggableAuthService.utils import classImplements


class SAML2PluginBase(BasePlugin):
    """ SAML 2.0 base plugin class """

    security = ClassSecurityInfo()

    def __init__(self, id, title=''):
        """ Initialize a new instance """
        self.id = id
        self.title = title


InitializeClass(SAML2PluginBase)

classImplements(IAuthenticationPlugin,
                IChallengePlugin,
                ICredentialsResetPlugin,
                IExtractionPlugin,
                IPropertiesPlugin,
                )

