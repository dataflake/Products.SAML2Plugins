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
""" Run-time monkey patches for various modules
"""

import logging
import os

from xmlschema.resources import XMLResource


logger = logging.getLogger('Products.SAML2Plugins')


def pysaml2_add_signature_support():
    from saml2 import entity
    from saml2 import xmldsig

    # pysaml2 has a hardcoded list of signature algorithms, but the xmlsec1
    # binary supports a lot more. Some Identity Providers require other
    # signature algorithms.
    additional_algs = ()
    for short_name, name in (
            ('SIG_SHA256_RSA_MGF1',  # required by Elster
             'http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1'),
       ):
        setattr(xmldsig, short_name, name)
        additional_algs += ((short_name, name),)
    xmldsig.SIG_ALLOWED_ALG = xmldsig.SIG_ALLOWED_ALG + additional_algs
    xmldsig.SIG_AVAIL_ALG = xmldsig.SIG_AVAIL_ALG + additional_algs
    entity.SIG_ALLOWED_ALG = xmldsig.SIG_ALLOWED_ALG


def pysaml_add_xml_schemata():
    from saml2.xml import schema

    # pysaml2 has a hardcoded list of supported XML schemata and namespaces,
    # which does not include newer versions.
    parent_folder_path = os.path.dirname(os.path.abspath(__file__))
    schema_data_folder = os.path.join(parent_folder_path, 'data')
    additional_schemata = ('xenc-schema-11.xsd',)
    schema_validator_default = schema._schema_validator_default

    for filename in additional_schemata:
        schema_path = os.path.join(schema_data_folder, filename)
        xml_resource = XMLResource(source=schema_path,
                                   base_url=schema_data_folder,
                                   allow='sandbox')
        schema_validator_default.add_schema(source=xml_resource, build=True)

    schema._schema_validator_default = schema_validator_default


def applyPatches():
    logger.debug('Applying monkey patches')
    pysaml2_add_signature_support()
    pysaml_add_xml_schemata()
