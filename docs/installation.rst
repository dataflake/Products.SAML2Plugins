Installation
============


Prerequisites
-------------
You need to have the ``xmlsec1`` and ``xmlsec1-openssl`` packages installed
before installing :mod:`Products.SAML2Plugins`.


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
