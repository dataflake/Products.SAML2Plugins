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
""" SAML metadata XML output creation
"""

import copy
from xml.dom.minidom import parseString

from saml2.config import Config
from saml2.metadata import entities_descriptor
from saml2.metadata import entity_descriptor
from saml2.metadata import metadata_tostring_fix
from saml2.metadata import sign_entity_descriptor
from saml2.sigver import security_context
from saml2.validate import valid_instance

from AccessControl import ClassSecurityInfo
from AccessControl.class_init import InitializeClass
from AccessControl.Permissions import manage_users


class SAML2MetadataProvider:

    security = ClassSecurityInfo()

    @security.protected(manage_users)
    def getMetadataZMIRepresentation(self):
        """ Returns a readable metadata representation for the ZMI """
        try:
            return self.generateMetadata()
        except Exception as exc:
            return (f'Error creating metadata XML:\n{exc}')

    @security.protected(manage_users)
    def generateMetadata(self):
        """ Generate XML metadata output from configuration

        The metadata generation assumes that a pysaml2 configuration only
        describes a single entity/service.

        Returns:
            An unencoded string representing the XML metadata description
        """
        nspair = {"xs": "http://www.w3.org/2001/XMLSchema"}
        config = copy.deepcopy(self.getConfiguration())
        xmldoc = None

        # Configuration for a single entity (XML EntityDescriptor element)
        entity_cfg = Config().load(config)
        entity = entity_descriptor(entity_cfg)

        if self.metadata_envelope:
            # To make sure signing information only shows up on the enclosing
            # envelope, remove it for the entity configuration.
            key_file = config.pop('key_file', '')
            cert_file = config.pop('cert_file', '')

            # Configuration for the XML EntityDescriptors envelope
            pysaml2_conf = Config()
            pysaml2_conf.key_file = key_file
            pysaml2_conf.cert_file = cert_file
            pysaml2_conf.debug = 1
            pysaml2_conf.xmlsec_binary = config.get('xmlsec1_binary')
            security_ctx = security_context(pysaml2_conf)

            entities, xmldoc = entities_descriptor([entity],
                                                   self.metadata_valid or 0,
                                                   '',  # name argument
                                                   self._uid,  # id argument
                                                   self.metadata_sign,
                                                   security_ctx)
            valid_instance(entities)
            xmldoc = metadata_tostring_fix(entities, nspair, xmldoc)
        else:
            valid_instance(entity)
            if self.metadata_sign:
                security_ctx = security_context(entity_cfg)
                entity, xmldoc = sign_entity_descriptor(
                                    entity, config['entityid'], security_ctx)
            xmldoc = metadata_tostring_fix(entity, nspair, xmldoc)

        if isinstance(xmldoc, bytes):
            xmldoc = xmldoc.decode("utf-8")

        # Transform to a pretty representation
        data_dom = parseString(xmldoc)
        return data_dom.toprettyxml(indent='  ')

        return xmldoc


InitializeClass(SAML2MetadataProvider)
