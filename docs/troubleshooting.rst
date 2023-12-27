Troubleshooting
===============

The correct function of a SAML 2.0 Plugin requires several cooperating
entities and configurations. There are many places where even a small
misconfiguration can make authentication fail. This document tells you how to
get more debugging information and where some of the traps are.

.. contents:: Document contents
    :local:


Turn on debug logging
---------------------

The plugin code itself as well as the :term:`pysaml2` library contain extensive
debug logging. This should not be enabled in production due to the sheer volume
of text written to the log.

By default, :term:`Zope` logs at log level ``INFO``. Lower levels such as
``DEBUG`` are not logged. To show ``DEBUG`` messages, edit your Zope instance's
WSGI configuration:

- If you used the script ``mkwsgiinstance`` edit the file at
  ``etc/zope.ini`` inside the folder you selected for the instance.
- If you used the buildout recipe ``plone.recipe.zope2instance`` to create
  the :term:`Zope` instance then edit the file at
  ``parts/<INSTANCENAME>/etc/wsgi.ini``, where ``<INSTANCENAME>`` is the name
  of the buildout section that builds the :term:`Zope` instance.

Find the section ``[logger_root]`` and change the value for the ``level``
setting from ``INFO`` to ``DEBUG``. Then restart your Zope instance. The log
output is sent to the event log, its path is shown in the WSGI configuration
section ``[handler_eventlog]``.

To follow output at the console it's usually simpler to run the Zope instance
attached to the terminal while debugging. For ``plone.recipe.zope2instance``
instances, use the start script with the argument ``fg`` instead of ``start``.


Errors shown on the Configuration tab
-------------------------------------

Some errors are shown on the plugin's `Configuration` :term:`ZMI` tab, like
missing or unreadable key and certificate files. Look there first.


Failures before identity provider redirection
---------------------------------------------

Some identity providers have specific requirements for the digest, signature
and/or encryption algorithms they accept. This can break the redirect from the
Zope plugin to the identity provider when those algorithms are not supported by
either :term:`pysaml2`, :term:`xmlsec1` or both. This error condition requires
watching the event log output from the :term:`pysaml2` library. You will see
parse errors that contain algorithm values or error output from the logged
``xmlsec1`` binary interaction.


Redirect to the identity provider fails
---------------------------------------

If Zope redirects to the identity provider but the identity provider throws up
an error message check the key/certificate settings. Make sure the key and
certificate files configured in the :term:`pysaml2` configurations for
``key_file`` and ``cert_file`` match what the identity provider expects. If you
are not sure, visit the `Metadata` :term:`ZMI` tab, download the plugin's
metadata file again and re-upload it at the identity provider.


Zope login fails
----------------

If the user is redirected correctly to the identity provider, but a successful
login there does not log the user into Zope and instead redirects back to the
identity provider then Zope was unable to read login information from the SAML
response sent by the identity provider.

If the Zope event log shows a message containing `handleACSRequest: Cannot find
login attribute` then you have configured `Login attribute` on the :term:`ZMI`
tab, but that attribute is not found among the attributes sent by the identity
provider. Set that configuration to an empty string, change the :term:`pysaml2`
configuration setting ``allow_unknown_attributes`` to ``True``, reload the
configuration and then re-try the login. Watch the :term:`pysaml2` log
messages for output starting with ``AVA``. It will show a mapping with the
attribute names and their values that were sent by the identity provider. Make
sure the attribute you set as `Login attribute` is in that map. If you have
configured the :term:`pysaml2` setting ``attribute_map_dir`` and use your own
attribute maps, make sure the SAML attribute names and the mapped names are
correct and the SAML syntax matches what the identity provider sends. To see
the attributes' SAML syntaxes watch the XML output :term:`pysaml2` logs to the
Zope event log.

In general, custom :term:`pysaml2` attribute maps in conjunction with
disallowing unknown attributes by setting ``allow_unknown_attributes`` to
``False`` should be tested thoroughly before deployment in production. Make
sure your custom attribute maps don't define more than a single map for each
SAML syntax. These maps are **not merged** during loading, only a single map
will be loaded for each syntax.

Some identity providers will use unsupported algorithms for digest, signature
and/or encryption. This error condition requires watching the
event log output from the :term:`pysaml2` library. You will see parse errors
that contain algorithm values or error output from the logged ``xmlsec1``
binary interaction.
