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
""" Dummy fixture classes for SAML2 plugin test classes
"""


class DummyResponse:

    def __init__(self):
        self.redirected = ''
        self.locked = False

    def redirect(self, target, lock=False):
        self.redirected = target
        self.locked = lock


class DummyRequest:

    def __init__(self):
        self.RESPONSE = DummyResponse()
