from saml2 import BINDING_HTTP_REDIRECT


CONFIG = {
    "entityid": "https://www.example.com",
    "service": {
        "sp": {
            "name": "Testing SP",
            "allow_unsolicited": False,
            "endpoints": {
                "assertion_consumer_service": [
                    "https://www.example.com/acs",
                ],
            },
        },
    },
    "key_file": "/opt/zope/etc/saml.key",
    "cert_file": "/opt/zope/etc/saml.crt",
    "xmlsec_binary": "/usr/local/bin/xmlsec1",
    "allow_unknown_attributes": True,
    "organization": {
        "display_name": [
            "example.com samltest1",
        ],
        "name": [
            "example.com samltest1",
        ],
        "url": [
            "https://www.example.com",
        ],
    },
    "contact_person": [
        {
            "givenname": "John",
            "surname": "Doe",
            "phone": "",
            "mail": "johndoe@example.com",
            "type": "technical",
        },
    ],
    "metadata": {
        "local": [
            "/opt/zope/etc/idp.xml",
        ],
    },
}
