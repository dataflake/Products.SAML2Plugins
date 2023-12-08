Installation
============


Prerequisites
-------------
You need to have the ``xmlsec1`` and ``xmlsec1-openssl`` packages installed
before installing :mod:`Products.SAML2Plugins`. The package names differ
between operating systems:

- macOS: ``brew install libxmlsec1``
- RedHat 9 and derivatives: ``dnf install xmlsec1 xmlsec1-openssl``
- Ubuntu 22.04: ``apt-get install xmlsec1``


Install with ``pip``
--------------------

.. code:: 

    $ pip install Products.SAML2Plugins


Install with ``zc.buildout``
----------------------------
Just add :mod:`Products.SAML2Plugins` to the ``eggs`` setting(s) in your
buildout configuration to have it pulled in automatically::

    ...
    eggs =
        Products.SAML2Plugins
    ...
