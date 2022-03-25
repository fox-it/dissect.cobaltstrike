Examples
========

Some examples showing how to use the ``dissect.cobaltstrike`` Python API.

.. ipython:: python
        :suppress:

        # setup some test data for this example
        import shutil
        import zipfile
        import pathlib

        p = pathlib.Path("../tests/beacons/4f571c0bc97c20eefc58fa3faf32148d.bin.zip")
        with zipfile.ZipFile(p) as zf:
            with zf.open(p.stem, pwd=b"dissect.cobaltstrike") as f:
                open("beacon_92.bin", "wb").write(f.read())

        p = pathlib.Path("../tests/beacons/1897a6cdf17271807bd6ec7c60fffea3.bin.zip")
        with zipfile.ZipFile(p) as zf:
            with zf.open(p.stem, pwd=b"dissect.cobaltstrike") as f:
                open("beacon_93.bin", "wb").write(f.read())

        p = pathlib.Path("../tests/beacons/3fdf92571d10485b05904e35c635c655.bin.zip")
        with zipfile.ZipFile(p) as zf:
            with zf.open(p.stem, pwd=b"dissect.cobaltstrike") as f:
                open("beacon_xor.bin", "wb").write(f.read())

        shutil.copy2("../tests/profiles/amazon.profile", ".")

Beacon Configuration
--------------------

The main class for dealing with Cobalt Strike Beacon configuration is :class:`~dissect.cobaltstrike.beacon.BeaconConfig`.
It's recommended to instantiate the class by using one of the following constructors:

 - :meth:`BeaconConfig.from_file() <dissect.cobaltstrike.beacon.BeaconConfig.from_file>`
 - :meth:`BeaconConfig.from_path() <dissect.cobaltstrike.beacon.BeaconConfig.from_path>`
 - :meth:`BeaconConfig.from_bytes() <dissect.cobaltstrike.beacon.BeaconConfig.from_bytes>`

These `from_` constructors will handle :class:`XorEncoded <dissect.cobaltstrike.xordecode>` beacons
by default and tries the default `XOR` keys used for obfuscating the beacon configuration. It raises
ValueError if no beacon config was found.

For example to load the configuration of a Beacon payload on disk and access it's settings:

.. ipython::

        In [1]: from dissect.cobaltstrike.beacon import BeaconConfig

        In [2]: bconfig = BeaconConfig.from_path("beacon_92.bin")

        In [3]: bconfig

        In [4]: bconfig.version

        In [5]: hex(bconfig.watermark)

        In [6]: bconfig.settings["SETTING_C2_REQUEST"]

If the beacon uses a non standard XOR key it will not find the beacon configuration and will raise :exc:`ValueError`:

.. ipython::
        :okexcept:

        In [7]: %xmode Minimal

        In [8]: bconfig = BeaconConfig.from_path("beacon_xor.bin")


Specify ``all_xor_keys=True`` to automatically try all single-byte XOR keys when the default keys fail:

.. ipython::

        @suppress
        In [0]: from dissect.cobaltstrike import beacon
           ...: ORG_DEFAULT_XOR_KEYS = beacon.DEFAULT_XOR_KEYS
           ...: beacon.DEFAULT_XOR_KEYS = [b"\xcc"]

        In [1]: bconfig = BeaconConfig.from_path("beacon_xor.bin", all_xor_keys=True)

        @suppress
        In [0]: beacon.DEFAULT_XOR_KEYS = ORG_DEFAULT_XOR_KEYS

        In [2]: bconfig

        In [3]: bconfig.xorkey.hex()

        In [4]: bconfig.version

Or if you want to speed things up and you know a set of candidate XOR keys, just specify them using ``xor_keys`` to
override the :attr:`~dissect.cobaltstrike.beacon.DEFAULT_XOR_KEYS`:

.. ipython::

        In [1]: BeaconConfig.from_path("beacon_xor.bin", xor_keys=[b"\xcc"])

        In [2]: _.xorkey.hex()

If you have extracted a Beacon configuration block manually, for example via `x64dbg`, you can pass it directly
to :meth:`~dissect.cobaltstrike.beacon.BeaconConfig`. However, this only works with configuration bytes that is not
obfuscated.

If the configuration block is obfuscated with a single-byte XOR key, use
the :meth:`BeaconConfig.from_bytes() <dissect.cobaltstrike.beacon.BeaconConfig.from_bytes>` constructor:

.. ipython::

        In [1]: data = '000000000000002e2f2e2f2e2c2e262e2c2e2f2e2c2f952e2d2e2c2e2a2e2ec44e2e2a2e2c2e2a2e3b7b762e2b2e2f2e2c2e302e292e2d2f2e1eafb11e23282704a866a8d9232f2f2f2b2e2dafa32e1eafa72cafaf2e889020f71e85a0e5a8d4e34a3795cda19b92a96ab5def70f62f93df6dc9630a2792be4a072feb87d581c02b171e1f5f869e40ea22cc29f1e77137f46199f49b70467f5f8d0901a7a321e92b6a3e5796ccd898a6b67f99d1861c6a0bf65e28e322f5b48a33edaed42ba921dcd6637560a4f309a8d1a313eeb9e0eae9e05e14cd52c2d2f2e2f2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e262e2d2f2e5d4740475a5b4a4b004d41430201594b4c014d464f5a5c005e415c5a4f422e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e202e2d2e3e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e332e2d2e6e0b5947404a475c0b725d575d594159181a724a424246415d5a004b564b2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e302e2d2e6e0b5947404a475c0b725d575d404f5a47584b724a424246415d5a004b564b2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e312e2f2e2c2e2e2e342e2d2e3e696b7a2e2e2e2e2e2e2e2e2e2e2e2e2e2e352e2d2e3e7e617d7a2e2e2e2e2e2e2e2e2e2e2e2e2e322e2c2e2a2e2e2e2e2e0b2e2c2e2a7f2791432e082e2f2e2c2e2e2e092e2f2e2c2e2e2e272e2d2f2e6341544742424f011b001e0e067947404a41595d0e607a0e18001c070e6f5e5e424b794b4c65475a011b1d19001d180e0665667a6362020e4247454b0e694b4d4541070e6d465c41434b01171e001e001a1a1d1e00161b0e7d4f484f5c47011b1d19001d182e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e242e2d2e6e01594b4c014241494140004f5d5e562e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e252e2d2f2e2e2e2e2a2e2e2e2d2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e222e2d2c2e2e2e2e242e2e2e396d41405a4b405a037a575e4b140e5a4b565a01465a43422e2e2e242e2e2e396d4f4d464b036d41405a5c4142140e4041034d4f4d464b2e2e2e292e2e2e2e2e2e2e262e2e2e222e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e232e2d2c2e2e2e2e242e2e2e0f6d41405a4b405a037a575e4b140e435b425a475e4f5c5a0148415c43034a4f5a4f2e2e2e242e2e2e396d4f4d464b036d41405a5c4142140e4041034d4f4d464b2e2e2e292e2e2e2e2e2e2e252e2e2e222e2e2e292e2e2e2f2e2e2e232e2e2e2a2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e182e2d2eae2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e1c2e2f2e2c2e2e2e0d2e2f2e2c2e2c2e142e2d2eae2e2bbe2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e172e2d2eae2e2b5e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e192e2f2e2c2e2e2e062e2c2e2a2e2e2e2e2e072e2c2e2a2e2e2e2e2e052e2f2e2c2e2a2e022e2f2e2c2e0e2e032e2c2e2a2e2e6a722e002e2d2f2e2e2e2e2cbebe2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e012e2d2f2e2e2e2e2cbebe2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e1b2e2d2e3e22ccdb7a6aca571b389b81c74990bc7b2e1d2e2d2eae282e082e2e2e28405a4a42422e2e2e2e3d7c5a427b5d4b5c7a465c4b4f4a7d5a4f5c5a2e2f26292e7f2e2e2e23454b5c404b421d1c004a42422e2e2e2e2362414f4a62474c5c4f5c576f2e2a2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e1a2e2f2e2c2e2f2e2ea9b00e0f83d6dcebcc255a8257385b0cfcd0b3e396662dbc1dfaa4760f06e45619877b1b8417ed572d4fb9dc3693800c78d5ad9efb6b49101afb1fcce586e1b08bb4bb746dd5114c2707c83b0b3cb571ba5d49ce24d84dc8c719c536d0491107dc284ba6ca8560274d4838c2fb866ef2a1875dead0f249885c0a7b1393dfc3630fb471753e907eef2ffeeb03bba60268453f444d83013fde9e95332e52fb82b1b59ecb31f2b83e90f6738ce1add1def1dddfee14c80445b2e2c5f9318d0efa7082519aa05fe2c3454ccb4950de6a924238bbeb9fe39721719f7ac8092087be5c2de004d6a39acc8135e86a13cac51e3448268a817742493aa3120059a109ef5e1812129f2c6d139a2b8859e8b40bc40eb643583bf993af9c7abaaa37450c426712337b1d18160be90b101698d1fd7b9928f593314b85117713222985f789362cdff09ea88cb167b72d1913961942e0d31ee2c8d256b4e4356d16fd5ea9f6bd42bb2ccb127db061f2003b5fc637873090180c951679a1bf8c8beae3203a6cc3c5638b8c5942bff2f7981b86798023f71d4e9acdd8b39d689c489445e8b9279a078fb6de1b8c527b339ef447039b1903b8b95ef5769502b9d7e0fd81d839c8903ad2244e4690e6839d9869301e0c2c0be9c725d8fb5d6cb96ac9cee3873ec5268c1eeed334317c01'

        In [2]: BeaconConfig.from_bytes(bytes.fromhex(data))

        In [3]: config = _

        In [4]: config.protocol

        In [5]: config.domain_uri_pairs

        In [6]: config.settings

        In [7]: config.version

Memory dumps
------------
While you can use :class:`~dissect.cobaltstrike.beacon.BeaconConfig` to load Beacon payloads directly,
it can also load a memory dump (or any other file) and check for beacon configurations.
However, the default constructors will only return the first found beacon configuration.

If you have a memory dump that could contain multiple beacons,
use :meth:`~dissect.cobaltstrike.beacon.iter_beacon_config_blocks` to iterate over all found beacon
configuration blocks and instantiate :class:`~dissect.cobaltstrike.beacon.BeaconConfig` manually:

.. code-block:: python

        import sys
        from dissect.cobaltstrike import beacon

        with open(sys.argv[1], "rb") as f:
            for config_block, extra_data in beacon.iter_beacon_config_blocks(f):
                try:
                    bconfig = beacon.BeaconConfig(config_block)
                    if not len(bconfig.domains):
                        continue
                except ValueError:
                    continue
                print(bconfig, bconfig.domain_uri_pairs)

This will try to find all beacon `config_block` bytes in the file and try to instantiate
a :class:`~dissect.cobaltstrike.beacon.BeaconConfig` from it. For verification it will
check if the beacon has a domain to ensure that `config_block` was not just some random data.

PE Artifacts
------------

Use the :mod:`dissect.cobaltstrike.pe` module to extract PE artifacts.
If the payload is `XorEncoded` you need to load it using :class:`~dissect.cobaltstrike.xordecode.XorEncodedFile` first.

.. ipython::

        In [0]: from dissect.cobaltstrike import xordecode

        In [0]: from dissect.cobaltstrike import pe

        In [0]: import time

        In [1]: xf = xordecode.XorEncodedFile.from_path("beacon_93.bin")

        In [2]: pe.find_architecture(xf)

        In [3]: pe.find_compile_stamps(xf)

        In [4]: compile_stamp, export_stamp = _

        In [5]: time.ctime(compile_stamp)

        In [6]: pe.find_magic_mz(xf)

        In [7]: pe.find_magic_pe(xf)

        In [8]: pe.find_stage_prepend_append(xf)

C2 Profiles
-----------

Loading Cobalt Strike Malleable C2 Profiles is also supported, to load a profile from disk:

.. ipython::

        In [1]: from dissect.cobaltstrike.c2profile import C2Profile

        In [2]: profile = C2Profile.from_path("amazon.profile")

To access the C2Profile configuration settings use
the :meth:`C2Profile.as_dict <dissect.cobaltstrike.c2profile.C2Profile.as_dict>` method or
the :attr:`C2Profile.properties <dissect.cobaltstrike.c2profile.C2Profile.properties>` attribute. For example:

.. ipython::

        In [1]: profile.as_dict()

        In [2]: profile.properties["useragent"]
        ['Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko']

        In [3]: profile.properties["http-get.uri"]
        ['/s/ref=nb_sb_noss_1/167-3294888-0262949/field-keywords=books']

        In [4]: profile.properties["http-post.client.parameter"]
        [('sz', '160x600'),
        ('oe', 'oe=ISO-8859-1;'),
        ('s', '3717'),
        ('dc_ref', 'http%3A%2F%2Fwww.amazon.com')]

.. note::

        Currently all the values in the dictionary are lists, this might change in the future.

BeaconConfig to C2 Profile
--------------------------

Use :meth:`C2Profile.from_beacon_config <dissect.cobaltstrike.c2profile.C2Profile.from_beacon_config>` to load
settings from a :class:`~dissect.cobaltstrike.beacon.BeaconConfig`. This allows for dumping the Beacon Configuration
to a more readable (and reusable) C2 Profile.

.. ipython::

        In [1]: config

        In [2]: profile = C2Profile.from_beacon_config(config)

        In [3]: print(profile)

Stager URIs and checksum8
-------------------------

`checksum8` URIs are used for payload staging and used in Cobalt Strike shellcode stagers for retrieving
the final Beacon payload from the Team Server.

.. note::
   `Metasploit`_ also uses *checksum8*, it exists in Cobalt Strike to be compatible with Metasploit.

.. _Metasploit: https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/payloads/meterpreter/uri_checksum.rb

The following *checksum8* values are used by Cobalt Strike:

+-----------+----------------------+
| checksum8 | architecture         |
+===========+======================+
| 92        | beacon x86           |
+-----------+----------------------+
| 93        | beacon x64           |
+-----------+----------------------+

To calculate the *checksum8* of an URI:

.. ipython::

        In [1]: from dissect.cobaltstrike import utils

        In [2]: utils.checksum8("/rLEZ")

        In [3]: utils.is_stager_x64("/rLEZ")

        In [4]: utils.is_stager_x86("/yearbook")


To easily generate valid Cobalt Strike stager URIs,
use :func:`utils.random_stager_uri <dissect.cobaltstrike.utils.random_stager_uri>`:

.. ipython::

        @suppress
        In [0]: import random; random.seed(1337)

        In [1]: from dissect.cobaltstrike import utils

        In [2]: utils.random_stager_uri(x64=True)

        In [3]: utils.random_stager_uri(length=30)

Or, a fun script to check a dictionary or word list for valid `stager x86` words:

.. code-block:: python

        import sys
        from dissect.cobaltstrike import utils

        for line in sys.stdin:
            line = line.strip().lower()
            if utils.is_stager_x86(line):
                print(line)

.. code-block:: bash

        $ cat /usr/share/dict/words | python is_stager_x86.py | head -n 10
        abortive
        abshenry
        accommodative
        acosmism
        acquirer
        acroaesthesia
        adance
        adiposis
        adoptive
        adulator
