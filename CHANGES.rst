Change log
==========

1.0 (unreleased)
----------------

- Added support for the SAML 2.0 Single Logout Service

- Removed support for Python 3.7 and 3.8:
  To avoid compatibility issues between ``pysaml2`` and ``xmlsec1`` versions
  this package now requires at least Python 3.9. The ``pysaml2`` package loaded
  on Python 3.7 and 3.8 is not compatible with ``xmlsec1`` version 1.3 and up.


0.9 (2023-12-28)
----------------

- Initial release for testing.
