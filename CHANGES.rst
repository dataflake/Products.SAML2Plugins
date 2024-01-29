Change log
==========

1.0 (unreleased)
----------------

- Check IdP metadata for a configured single logout service before logging out.

- Add method ``isLoggedInHere`` to see if the current user is from the plugin.

- Use the PySAML2 `valid_until` configuration instead of a custom property
  on the plugin itself to set a metadata timeout value.

- Add the missing Title property on the ZMI Properties tab.

- Fix ZMI views failing with bad PySAML2 configurations
  (`#1 <https://github.com/dataflake/Products.SAML2Plugins/issues/1>`_)

- Added support for the SAML 2.0 Single Logout Service

- Removed support for Python 3.7 and 3.8:
  To avoid compatibility issues between ``pysaml2`` and ``xmlsec1`` versions
  this package now requires at least Python 3.9. The ``pysaml2`` package loaded
  on Python 3.7 and 3.8 is not compatible with ``xmlsec1`` version 1.3 and up.


0.9 (2023-12-28)
----------------

- Initial release for testing.
