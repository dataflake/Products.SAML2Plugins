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

.. note::

    If you need to support newer digest, signature or encryption algorithms
    make sure to install :term:`xmlsec1` version 1.3.0 or higher. The
    German Elster Identity Provider, for example, requires algorithms not 
    supported by earlier versions.


Building :term:`xmlsec1` from source
------------------------------------

If you `build xmlsec1 from source
<https://www.aleksey.com/xmlsec/download.html>`_ in non-standard filesystem
locations you may run into issues loading the library. On Linux you can set the
environment variable ``LD_LIBRARY_PATH`` to the path where the library can be
loaded. For example, if you set the ``--prefix`` configure script setting to
``/home/zope/local`` the :term:`xmlsec1` library will be installed into
``/home/zope/local/lib``. To find it, set
``LD_LIBRARY_PATH=/home/zope/local/lib``. If you use
``plone.recipe.zope2instance`` to build your :term:`Zope` instance, simply add
the following to its buildout section to set the variable automatically:

.. code:: ini

    ...
    environment-vars =
        LD_LIBRARY_PATH /home/zope/local/lib
    ... 


Install with ``pip``
--------------------

.. code:: 

    $ pip install Products.SAML2Plugins


Install with ``zc.buildout``
----------------------------
Just add :mod:`Products.SAML2Plugins` to the ``eggs`` setting(s) in your
buildout configuration to have it pulled in automatically:

.. code:: ini

    ...
    eggs =
        Products.SAML2Plugins
    ...
