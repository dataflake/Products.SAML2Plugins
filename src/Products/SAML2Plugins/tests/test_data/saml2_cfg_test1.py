from saml2 import BINDING_HTTP_REDIRECT


CONFIG = {
    "entityid": "http://example.com/sp/metadata.xml",
    "service": {
        "sp": {
            "name": "Example SP",
            "endpoints": {
                "assertion_consumer_service": [
                    "http://example.com/sp",
                ],
            },
        },
    },
    "key_file": "./mykey.pem",
    "cert_file": "./mycert.pem",
    "xmlsec_binary": "/usr/local/bin/xmlsec1",
    "delete_tmpfiles": True,
    "metadata": {
        "local": [
            "idp.xml",
        ],
    },
    "organization": {
        "display_name": [
            "Example identities",
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
