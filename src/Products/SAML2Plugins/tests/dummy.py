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


class DummySession(dict):

    def set(self, key, value):
        self[key] = value


class DummyUser:

    def __init__(self, name):
        self.name = name

    def getId(self):
        return self.name


class DummyResponse:

    def __init__(self):
        self.redirected = ''
        self.locked = False
        self.headers = {}
        self.status = None

    def redirect(self, target, status=302, lock=False):
        self.redirected = target
        self.locked = lock
        self.status = status

    def setHeader(self, name, value):
        self.headers[name] = value


class DummyRequest:

    def __init__(self):
        self.RESPONSE = self.response = DummyResponse()
        self.SESSION = DummySession()
        self.data = {}

    def set(self, key, value):
        self.data[key] = value

    def get(self, key, default=None):
        return self.data.get(key, default)


class DummyNameId:

    def __init__(self, name):
        self.name = name
        self.name_qualifier = 'name_qualifier_value'
        self.sp_name_qualifier = 'sp_name_qualifier_value'
        self.format = 'format_value'
        self.sp_provided_id = 'sp_provided_id_value'
        self.text = name


class DummyPySAML2Client:

    def __init__(self):
        self.users = {}

    def _store_name_id(self, name_id):
        self.users[str(name_id)] = True

    def is_logged_in(self, name_id):
        return bool(self.users.get(str(name_id)))

    def local_logout(self, name_id):
        del self.users[str(name_id)]
