from saml2 import BINDING_HTTP_REDIRECT


CONFIG = {
    "entityid": "http://sp.example.com/metadata.xml",
    "service": {
        "sp": {
            "name": "Example SP",
            "endpoints": {
                "assertion_consumer_service": [
					"http://sp.example.com/",
                ],
            },
            "subject_data": [
                "memcached",
                "localhost:12121",
            ],
            "virtual_organization": {
                "urn:mace:example.com:it:tek": {
                    "nameid_format": "urn:oid:1.3.6.1.4.1.1466.115.121.1.15-NameID",
                    "common_identifier": "eduPersonPrincipalName",
                },
            },
        },
    },
    "key_file": "./mykey.pem",
    "cert_file": "./mycert.pem",
    "xmlsec_binary": "/usr/local/bin/xmlsec1",
    "delete_tmpfiles": True,
    "attribute_maps": "attributemaps",
    "organization": {
        "name": [
            "Example Identities",
        ],
        "display_name": [
            "Example identities",
        ],
        "url": [
            "http://www.example.com",
        ],
    },
    "contact_person": [
        {
            "givenname": "John",
            "surname": "Doe",
            "phone": "+1 800 555 1212",
            "mail": "johndoe@example.com",
            "type": "technical",
        },
    ],
}
