Beacon test data
================

This directory contains real Cobalt Strike beacon payloads, used as fixtures for unit test purposes.
The beacons payload are malicious by nature and therefore zipped using a password.

The password is ``dissect.cobaltstrike`` and future zipped beacon fixtures should use the same password.

Conventions
-----------

The beacon filename in the Zip should always be:

- ``<md5sum>.bin``

The zip filename should always be:

- ``<md5sum>.bin.zip``

Zip is compressed using the maximum compression ratio and with a password, e.g. using 7-zip:


.. code-block:: bash

    $ 7z a -pdissect.cobaltstrike -mx=9 <md5sum>.bin.zip <md5sum>.bin

Pytest fixtures
---------------

All beacon fixtures has to be added to the `beacons` dictionary in the `conftest.py` file::

        beacons = {
            # x86 beacon
            "beacon_x86": "4f571c0bc97c20eefc58fa3faf32148d.bin.zip",
            # x64 beacon
            "beacon_x64": "1897a6cdf17271807bd6ec7c60fffea3.bin.zip",
            # x86, custom xor key, stage prepend and append, custom MZ, custom PE
            "beacon_custom_xorkey": "3fdf92571d10485b05904e35c635c655.bin.zip",
            # dns beacon, custom xor key 0xaf, CS v4.3
            "dns_beacon": "a1573fe60c863ed40fffe54d377b393a.bin.zip",
            # c2test beacon, beacon used in test_c2.py
            "c2test_beacon": "37882262c9b5e971067fd989b26afe28.bin.zip",
            # beacon with unicode in domain
            "punycode_beacon": "5a197a8bb628a2555f5a86c51b85abd7.bin.zip",
            # guardrails protected beaon
            "guardrails_beacon": "124552cf674b362e0c916ab79b9e7a56.bin.zip",
        }

This dictionary is used to create dynamic fixtures based on the key name.
The following fixtures are automatically created by code in ``conftest.py``:

- ``{name}_file`` -- file object to the beacon file
- ``{name}_path`` -- path to extracted beacon file on disk
