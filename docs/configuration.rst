Configuration
=============

Successfully implementing SAML 2.0 support requires correct configurations on
several levels. This page provides an overview and examples.

- Where to store the filesystem configuration files can be defined in the
  :term:`Zope` configuration ``zope.conf``, otherwise the default configuration
  file folder for the :term:`Zope` instance is used.
- The :term:`pysaml2` library that does all the heavy lifting has its own set of
  filesystem-based configuration files, these get stored in the folder
  configured in ``zope.conf``.
- The plugin instances in the ZODB expose a few configuration settings in the
  :term:`Zope` Management Interface (ZMI).
- How the plugin acts in concert with other plugins in the respective
  `PluggableAuthService user folder
  <https://pypi.org/project/Products.PluggableAuthService/>`_ is configured on
  the plugin and the ``plugins`` object inside the user folder.
- The plugin stores user data on the respective users' :term:`Zope` sessions,
  so if your deployment uses :term:`ZEO` and multiple :term:`Zope` processes
  you should choose a session product that works across multiple processes,
  for example a :mod:`memcache`-based implementation.

.. contents:: Document contents
    :local:



Filesystem configuration location
---------------------------------

By default, the :term:`pysaml2` library configuration files are stored in the
:term:`Zope` instance ``INSTANCE_HOME`` subfolder ``etc``. In a
:term:`zc.buildout`-based installation this is usually in the buildout root's
subfolder ``parts/<INSTANCENAME>/etc``, where ``<INSTANCENAME>`` is the name
of the buildout section that builds the :term:`Zope` instance. If you want to
store the configurations elsewhere you can do so with a ``zope.conf`` setting:

.. code::

    <product-config saml2plugins>
      configuration_folder /opt/zope/mybuildout/etc
    </product-config>

If you use the buildout recipe ``plone.recipe.zope2instance`` to create the
:term:`Zope` instance you can add this configuration with the configuration key
``zope-conf-additional`` before running the buildout:

.. code::

    zope-conf-additional =
        <product-config saml2plugins>
          configuration_folder /opt/zope/mybuildout/etc
        </product-config>


pysaml2 configuration files
---------------------------

The :term:`pysaml2` library (https://pypi.org/project/pysaml2/) handles all SAML
2.0 interactions. It uses `its own set of configuration files
<https://pysaml2.readthedocs.io/en/latest/howto/config.html>`_, starting with
the main configuration file written in Python.

.. note::

    In order to support different configurations per plugin instance the
    main :term:`pysaml2` configuration file name is hardcoded for each plugin.
    The file name and location is shown on the ZMI tab `Configuration`:

    .. image:: _static/configuration_path.png

    This implies that you must create the SAML 2.0 plugin instance before you
    can create the :term:`pysaml2` configuration.

You should study the `pysaml2 configuration reference
<https://pysaml2.readthedocs.io/en/latest/howto/config.html>`_ to get an
overview over the different options. Here's some additional information:

- Any place where you configure file paths it is recommended you use absolute
  full paths instead of relative paths. Relative paths will be interpreted in
  the context of the current working path of the running Zope process, which
  may not always be obvious or the same.

- ``allow_unsolicited``: The ability to accept SAML requests from an identity
  provider that are not in response to a prior request by the service provider
  is mostly useful for testing. This should be set to `False` in production.
- ``key_file`` and ``cert_file``: The key and certificate files configured here
  are used for signing. If you don't specify a separate key and certificate
  file using the ``encryption_keypairs`` setting, they are used for encryption
  as well. You can generate suitable key/certificate pairs with `openssl`:

  .. code:: console

    openssl req -nodes -new -x509 -keyout samltest1.key -out samltest1.pem

- ``allow_unknown_attributes``: If set to `True`, all attributes returned by
  the identity provider are stored in the Zope user session. To limit the
  attributes and optionally map their names for Zope, you can use the
  ``attribute_map_dir`` setting to configure a folder where the attribute maps
  are stored. You should pay attention to the following:

  - If you don't specify an ``attribute_map_dir``, :term:`pysaml2` will load a
    default set of attributes. Every identity provider has different attribute
    names and syntaxes, so if you set ``allow_unknown_attributes`` to `False`
    logins may fail because none of the attributes returned by your specific
    identity provider match the attribute names assumed by :term:`pysaml2`.

  - Attribute maps are keyed on SAML 2.0 syntax names such as
    `urn:oasis:names:tc:SAML:2.0:attrname-format:uri`. You can store as many
    attribute map files in the configured folder as you like, but the map
    values for a given syntax name **are not merged after reading the file!**
    Instead, the last map encountered for a syntax name "wins". You should
    avoid having more than one file for each syntax.

- ``metadata``: This setting can hold as many XML file sources (local or
  remote) as you like. However, keep in mind how attribute maps are handled.
  It's not a good idea to separate attribute maps by identity provider - see
  the notes about attribute map handling above. The contents for these metadata
  files are available from your identity provider.


Plugin configuration in the ZMI
-------------------------------

After instantiating a `SAML 2.0 Plugin` in a :term:`PluggableAuthService`
instance you can configure several settings on its `Properties` :term:`ZMI`
tab:

- `Plugin unique ID (read-only)`: The plugin's unique ID, which determines the
  configuration file name for the main :term:`pysaml2` configuration file (see
  above).
- `Title (optional)`: An optional title for the plugin instance, which is
  visible in the :term:`ZMI`.
- `Default Identity Provider`: The selection list will show all identity
  providers that have been configured using the :term:`pysaml2` configuration
  key `metadata`. The identity provider you select here will be chosen by
  default. If you want to choose another you can present custom login links for
  them in your application.
- `Login attribute`: Zope user folders have a hardwired concept of a login
  value that is unique for each user. You can designate a SAML attribute name
  to use as this login, the attribute value should be unique for each user.
  If none is specified, Zope will use the so-called SAML
  2.0 `subject` value, which is a unique identity provider-assigned value.
- `Session inactivity timeout`: The number of hours of user inactivity until a
  session is considered stale and the user is forced to log in again. The
  timer is reset whenever the user performs some action on the site, such as
  loading a page.
- `Roles for SAML-authenticated users`: Once a user has successfully gone
  through the login procedure at the identity provider, Zope knows
  "this is a valid user". The site administrator may want to confer specific
  rights to these users. The selection list presents roles known to Zope in the
  place where the user folder was instantiated. All roles you select here will
  be given to users authenticated by this SAML 2.0 plugin.
- `Logout redirect path`: If you enter the path to a page in Zope here, the
  user will be redirected to that page when using the logout functionality.
  The page must be publicly visible because the user will be logged out at that
  moment, otherwise they will be prompted for authentication again.
- `Sign metadata`: If this checkbox is selected, the generated XML metadata is
  signed with the signing key from the :term:`pysaml2` ``key_file``
  configuration.
- `Use enclosing metadata EntitiesDescriptor`: The generated XML metadata
  describes the plugin's service provider functionality inside an
  `EntityDescriptor` XML tag. Checking this box will wrap that tag inside a
  container tag `EntitiesDescriptor`. This should usually stay unchecked
  because many identity providers don't support it.
- `Optional Prefix`: A :term:`PluggableAuthService`-specific setting to add a
  plugin-specific prefix to login values emitted by this plugin. This prevents
  naming collisions in cases where you have more than one plugin that emits
  logins and they define logins with the same name.


PluggableAuthService configuration
----------------------------------

Individual plugins can fulfill specific duties inside a
:term:`PluggableAuthService` user folder. Activating the different
functionalities is done on the plugin's `Activate` ZMI tab. Fine-tuning the
order in which the plugins are called for each functionality is done on the
``plugins`` object inside the :term:`PluggableAuthService` object. These
details are out of scope for this plugin documentation, though.

In general, you should check all boxes on this plugin's `Activate` tab with one
exception: You should only check the `Challenge` checkbox if the SAML 2.0
plugin is the only plugin that should present a login dialog to the users of
your site. If more than one plugin that is capable of presenting a login dialog
is selected then your users may see more than one login dialog, which is
probably not what you want.

If you want to support more than one way of logging into your site you should
only have one plugin that fulfills the `Challenge` role as fallback that gets
called automatically when a users visits a page they don't have enough rights
to see. For all others you should offer explicit links the user can click to
authenticate with the chosen mechanism. These links point to the respective
plugin's ``challenge`` method.

Alternatively, you could create and activate a custom challenge plugin using
e.g. a `Scriptable Plugin`, which does nothing but bring up a custom login
page where users can choose how to log in with login links.

.. note::

    The SAML 2.0 plugin does not support assigning roles or groups using the
    ZODB-based role and groups plugins that ship with the
    :term:`PluggableAuthService` because they require the ability to search for
    users. This is not supported by SAML 2.0. Users are essentially ephemeral
    and not persistent on the service provider side (the plugin). They only
    exist for the duration of the Zope login session.


Zope sessioning configuration
-----------------------------

The SAML 2.0 plugin stores successful login data and user attributes received
from the identity provider in the Zope session tied to that user. Keep in mind
that the default sesion implementation will store sessions in memory and not in
some shared database. That means session data is only available to the Zope
instance where the user logged in. If your deployment uses more than a single
Zope instance in a :term:`ZEO` configuration you should switch from the default
session implementation to one that stores data in a shared database. One good
choice is the memcache-based `Products.mcdutils
<https://pypi.org/project/Products.mcdutils/>`_ Zope add-on.
