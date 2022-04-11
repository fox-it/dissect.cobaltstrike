Dissecting Cobalt Strike using Python
=====================================

.. image:: https://github.com/fox-it/dissect.cobaltstrike/workflows/Tests/badge.svg
   :target: https://github.com/fox-it/dissect.cobaltstrike/actions
   :alt: GitHub Actions status
.. image:: https://readthedocs.org/projects/dissect-cobaltstrike/badge/?version=latest
   :target: https://dissect-cobaltstrike.readthedocs.io/en/latest/?badge=latest
   :alt: Documentation Status
.. image:: https://img.shields.io/pypi/v/dissect.cobaltstrike.svg
   :target: https://pypi.python.org/pypi/dissect.cobaltstrike

**dissect.cobaltstrike** is a Python library for dissecting and parsing Cobalt Strike related data such as beacon payloads and Malleable C2 Profiles.

Installation
------------

The library is available on PyPI. Use ``pip`` to install it::

    $ pip install dissect.cobaltstrike

**dissect.cobaltstrike** requires Python 3.6 or later.

Documentation
-------------

The project documentation can be found here: https://dissect-cobaltstrike.readthedocs.io

Basic Usage
-----------

Parse a Cobalt Strike beacon and extract some config settings:

.. code-block:: python

    >>> from dissect.cobaltstrike.beacon import BeaconConfig

    >>> bconfig = BeaconConfig.from_path("beacon.bin")

    >>> hex(bconfig.watermark)
    '0x5109bf6d'
    >>> bconfig.protocol
    'https'
    >>> bconfig.version
    <BeaconVersion 'Cobalt Strike 4.2 (Nov 06, 2020)', tuple=(4, 2), date=2020-11-06>

    >>> bconfig.settings
    mappingproxy({'SETTING_PROTOCOL': 8,
                  'SETTING_PORT': 443,
                  'SETTING_SLEEPTIME': 5000,
                  'SETTING_MAXGET': 1048576,
                  'SETTING_JITTER': 0, ...

    >>> bconfig.settings["SETTING_C2_REQUEST"]
    [('_HEADER', b'Connection: close'),
     ('_HEADER', b'Accept-Language: en-US'),
     ('BUILD', 'metadata'),
     ('MASK', True),
     ('BASE64', True),
     ('PREPEND', b'wordpress_ed1f617bbd6c004cc09e046f3c1b7148='),
     ('HEADER', b'Cookie')]

Parse a Malleable C2 Profile and read some configuration settings:

.. code-block:: python

    >>> from dissect.cobaltstrike.c2profile import C2Profile
    >>> profile = C2Profile.from_path("amazon.profile")
    >>> profile.as_dict()
    {'sleeptime': ['5000'],
     'jitter': ['0'],
     'maxdns': ['255'],
     'useragent': ['Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko'],
     'http-get.uri': ['/s/ref=nb_sb_noss_1/167-3294888-0262949/field-keywords=books'],
     'http-get.client.header': [('Accept', '*/*'), ('Host', 'www.amazon.com')],
     ...
    }
 
    >>> profile.properties["useragent"]
    ['Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko']

    >>> profile.properties["http-get.uri"]
    ['/s/ref=nb_sb_noss_1/167-3294888-0262949/field-keywords=books']

License
-------

**dissect.cobaltstrike** is developed and distributed under the MIT license.
