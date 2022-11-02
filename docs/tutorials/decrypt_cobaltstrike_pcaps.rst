===========================
Decrypt Cobalt Strike PCAPs
===========================

In this tutorial we will show how to decrypt a beacon session in a PCAP file using a known RSA Private key with the
CLI tool ``beacon-pcap`` that is installed by the ``dissect.cobaltstrike`` package.

There are some prerequisites to be able to decrypt Cobalt Strike C2 traffic:

* The beacon payload of the session that can be loaded by :class:`~dissect.cobaltstrike.beacon.BeaconConfig`.

  * If not specified it will try to find a staged beacon payload in the PCAP.

* One of the following Cryptographic keys is required:

  * AES key of the beacon session (HMAC key is optional)
  * AES rand bytes of the beacon session (this can derive both the AES and HMAC key)
  * RSA Private key of the Team Server (this can decrypt the BeaconMetadata for all sessions)

* If the C2 traffic is over HTTPS/TLS then a ``SSLKEYLOGFILE`` is also required.

Installation
============
This tutorial will take care of the requirements above, so let's get started.
First we ensure that we have ``dissect.cobaltstrike`` installed with PCAP support:

.. code-block:: bash

   $ pip install dissect.cobaltstrike[pcap]

This also installs the ``pyshark`` Python package but it still requires the ``tshark`` binary from Wireshark_ to work.
Ensure that you have Wireshark_ installed or install the ``tshark`` binary, for example on Ubuntu or Debian systems you can install it with:

.. _Wireshark: https://www.wireshark.org/

.. code-block:: bash

   $ apt install tshark

Verify that ``beacon-pcap`` runs by passing it ``--help``:

.. code-block:: bash

   $ beacon-pcap --help
   usage: beacon-pcap [-h] [-f FILTER] [-c C2] [-n NSS_KEYLOG_FILE] [-a AES] [-m HMAC] [-k] [-p PRIVATE_KEY] [-b BEACON] [-A] [-v] [-e] [-w WRITER] PCAP

   positional arguments:
     PCAP                  PCAP to parse

   optional arguments:
     -h, --help            show this help message and exit
     -f FILTER, --filter FILTER
                           Wireshark display filter to apply while parsing PCAP (default: None)
     -c C2, --c2 C2        Cobalt Strike C2 ip address (default: None)
     -n NSS_KEYLOG_FILE, --nss-keylog-file NSS_KEYLOG_FILE
                           NSS keylog file to use for decrypting SSL traffic (default: None)
     -a AES, --aes AES     AES key to use (in hex) (default: None)
     -m HMAC, --hmac HMAC  HMAC key to use (in hex) (default: None)
     -k, --no-hmac-verify  Disable HMAC signature verification (default: False)
     -p PRIVATE_KEY, --private-key PRIVATE_KEY
                           Path to RSA private key (default: None)
     -b BEACON, --beacon BEACON
                           Use the BeaconConfig from this Beacon (default: None)
     -A, --all-metadata    Dump all metadata and not only unique (default: False)
     -v, --verbose         Increase verbosity (default: 0)
     -e, --extract-beacons
                           Extract found beacons in pcap (default: False)
     -w WRITER, --writer WRITER
                           Record writer (default: None)

Getting the Beacon
==================

The PCAP we are going to use is from `Malware Traffic Analysis` and can be downloaded from here:

* https://www.malware-traffic-analysis.net/2021/06/15/index.html

.. code-block:: bash

   $ wget https://www.malware-traffic-analysis.net/2021/06/15/2021-06-15-Hancitor-with-Ficker-Stealer-and-Cobalt-Strike.pcap.zip
   $ 7z x 2021-06-15-Hancitor-with-Ficker-Stealer-and-Cobalt-Strike.pcap.zip -pinfected

After the PCAP is extracted we can do a preliminary analysis to find any staged beacon payloads in the PCAP and extract them:

.. code-block:: bash

   $ beacon-pcap --extract-beacons 2021-06-15-Hancitor-with-Ficker-Stealer-and-Cobalt-Strike.pcap
   [+] Found <BeaconConfig ['5.252.177.17']> at b'/ZsDK', extracted beacon payload to 'beacon-ZsDK.bin'
   [+] Found <BeaconConfig ['5.252.177.17']> at b'/8mJm', extracted beacon payload to 'beacon-8mJm.bin'

We see two beacons being extracted, this most likely indicates that there are two beacon sessions in the PCAP.
If you don't provide ``--extract-beacons`` then it will try to find the (first) staged beacon payload in the PCAP and
uses that to parse the C2 traffic.

.. hint::

   If no beacons are found in a PCAP you could try looking for the beacon config in
   the `Cobalt Strike Beacon Dataset <https://github.com/fox-it/cobaltstrike-beacon-data>`_ and extract the ``config_block`` field.

The beacon is required as it contains the configuration on how to communicate with it's Team Server and thus is needed
to be able to correctly parse and decrypt the C2 traffic in the PCAP.

RSA Private Key
===============

Now that the beacons are extracted, we inspect the `RSA Public Key` of the beacons using:

.. code-block:: bash

   $ beacon-dump -t raw beacon-8mJm.bin | grep PUBKEY
   <Setting index=<BeaconSetting.SETTING_PUBKEY: 7>, type=<SettingsType.TYPE_PTR: 3>, length=0x100, value=b"0\x81\x9f0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x81\x8d\x000\x81\x89\x02\x81\x81\x00\xa78\xcd\xe7_\x1f\xbb\x1c\x18dl7~\x03\x01k\x16+\x12\xbar\xbd\xf7\xdc6\xb4\xcd.N\x9b\xae\x12 Z\x95\xc2ap\xbf\x90\x81\x05\xad\x7f\xa4\xbb\xcc\xfay\x862&\x1b\xed\x98p\xf9u\xf2\x07\x94\xe1\xfeI\x95#\xd7\x1f\x08\xa5l\xae\x03\x15\xbf\xde=l\x8a\x168k\x03\xb7\xa6U\x1a\xa13mP2Z5\x00\xdb'\xd7\x8a\xd8\xfd\x13\xb6\xa7;\x9f\xb7\xc3\xfbMz\x08\x8e2?\x07a\x86V\xec\xd85\x95\xfa_\x826\x13\x02\x03\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00">

Our goal is to find out if we can find a matching **RSA Private key** on VirusTotal. When we query VirusTotal for the Public Key bytes we can
find that there are some malware samples but also a file called ``Cobalt Strike 4.3.zip``.

.. figure:: ../images/vt-cobaltstrike-43-zip.png

   Leaked version of Cobalt Strike 4.3 on VirusTotal (hash redacted)

This is a leaked version of Cobalt Strike containing a file called ``.cobaltstrike.beacon_keys``, embedded in this file is a **RSA Private key**.
which we can extract using the following Python script :doc:`dump_beacon_keys.py <../scripts/dump_beacon_keys>`

.. code-block:: shell

    $ file .cobaltstrike.beacon_keys
    .cobaltstrike.beacon_keys: Java serialization data, version 5

    $ python3 dump_beacon_keys.py
    -----BEGIN RSA PRIVATE KEY-----
    MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKc4zedfH7scGGRsN34DAWsWKxK6
    cr333Da0zS5Om64SIFqVwmFwv5CBBa1/pLvM+nmGMiYb7Zhw+XXyB5Th/kmVI9cfCKVsrgMVv949
    bIoWOGsDt6ZVGqEzbVAyWjUA2yfXitj9E7anO5+3w/tNegiOMj8HYYZW7Ng1lfpfgjYTAgMBAAEC
    gYBZ63DFTuB4NBZlwc9hQmp71BLbYkkbH/JZtIV0ti5+vx6It2ksDn3kTYzpC+9gUUwLFv9WgMQV
    qgJqyvgKti+PMGmMcTJTDd1GpEt3dzhwNzEuScWdxaAOIJZ0NfdMrGcDogHsNDG4YAjg2XP6d1eZ
    vHuIYwNycKM4KcCB5suqEQJBAOJdR3jg0eHly2W+ODb11krwbQVOxuOwP3j2veie8tnkuTK3Nfwm
    Slx6PSp8ZtABh8PcpRw+91j9/ecFZMHC6OkCQQC9HVV20OhWnXEdWspC/YCMH3CFxc7SFRgDYK2r
    1sVTQU/fTM2bkdaZXDWIZjbLFOb0U7/zQfVsuuZyGMFwdwmbAkBiDxJ1FL8W4pr32i0z8c8A66Hu
    mK+j1qfIWOrvqFt/dIudoqwqLNQtt25jxzwqg18yw5Rq5gP0cyLYPwfkv/BxAkAtLhnh5ezr7Hc+
    pRcXRAr27vfp7aUIiaOQAwPavtermTnkxiuE1CWpw97CNHE4uUin7G46RnLExC4T6hgkrzurAkEA
    vRVFgcXTmcg49Ha3VIKIb83xlNhBnWVkqNyLnAdOBENZUZ479oaPw7Sl+N0SD15TgT25+4P6PKH8
    QE6hwC/g5Q==
    -----END RSA PRIVATE KEY-----

    $ python3 dump_beacon_keys.py > key.pem

Decrypt C2 Traffic
==================

After extracting this key we have the `RSA Private Key` in PEM format that we can use to decrypt beacon sessions by
passing it to ``beacon-pcap`` using the ``-p / --private-key`` argument. It accepts both DER and PEM formatted key files.

.. code-block:: bash

    $ beacon-pcap -p key.pem 2021-06-15-Hancitor-with-Ficker-Stealer-and-Cobalt-Strike.pcap --beacon beacon-8mJm.bin
    <Beacon/BeaconMetadata packet_ts=2021-06-15 15:08:55.172675 src_ip=net.ipaddress('10.0.0.134') src_port=52886 dst_ip=net.ipaddress('5.252.177.17') dst_port=443 raw_http=b'GET /activity HTTP/1.1\r\nAccept: */*\r\nCookie: kR/OTFMhCYQpv09cXl2R7qEespVUfQ/8YahAbs1b+rEESbSzcAc44R9Klf4zH4GGYxT4dErzNQWimmMW5wQVQSEGFZ36mWc/beoUTQUGVUxcZWXl0t8WBO12qC6vsmRSV5uQO+qxz0Lbz1P/wOkWwbNM0XF9LhVjRrGYSR0Jlrc=\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 2.0.50727)\r\nHost: 5.252.177.17:443\r\nConnection: Keep-Alive\r\nCache-Control: no-cache\r\n\r\n' magic=48879 size=92 aes_rand=b'\xf9dA\xc8\x8b\x07\xe1:\xfa\np\xbc{`m\xe0' ansi_cp=58372 oem_cp=46337 bid=693615746 pid=6396 port=0 flag=4 ver_major=10 ver_minor=0 ver_build=19042 ptr_x64=0 ptr_gmh=1972243040 ptr_gpa=1972237648 ip=net.ipaddress('134.5.7.10') info=b'DESKTOP-X9JH6AW\ttabitha.gomez\tsvchost.exe'>
    <Beacon/TaskPacket packet_ts=2021-06-15 15:09:56.371968 src_ip=net.ipaddress('5.252.177.17') src_port=443 dst_ip=net.ipaddress('10.0.0.134') dst_port=52894 raw_http=b'HTTP/1.1 200 OK\r\nDate: Tue, 15 Jun 2021 15:09:55 GMT\r\nContent-Type: application/octet-stream\r\nContent-Length: 48\r\n\r\nP\xc1\xf1\xa0{3 \xa8\x01}\xfe\xbcl\x8e\xa2\x81\xd7A2\xa3;\xe0\x91\xf5\x90\xdd]\xc5\x88`\xa2\x88\x93\x14-\xb4\xbb\x96\xf1\x1c\xd7\r\xa60\xfe\xc5\x9e\xd6' epoch=2021-06-15 15:09:55 total_size=16 command='COMMAND_SLEEP' size=8 data=b'\x00\x00\x00d\x00\x00\x00Z'>

We specify a beacon specifically as there are two beacon sessions in this PCAP but they have slightly different urls.
If you want to decrypt the other session just pass the other beacon as the parameter using ``--beacon``.

Export C2 traffic as records
============================

By default ``beacon-pcap`` will output decrypted C2 traffic to stdout as `flow.record` format.
You can redirect the records to a file or write them to a file using ``-w / --writer`` or even pipe it directly to ``rdump``.

Example of writing the decrypted C2 records to the file ``c2.records.gz``:

.. code-block:: bash

   $ beacon-pcap -w c2.records.gz -p key.pem 2021-06-15-Hancitor-with-Ficker-Stealer-and-Cobalt-Strike.pcap --beacon beacon-8mJm.bin

.. hint::

   By specifying ``.gz`` as the filename extension the file is automatically ``gzip`` compressed by ``flow.record``.
   It supports many other compression algorithms, such as ``bz2``, ``lz4`` and ``zstd``.
   However, they might need additional dependencies.

Dumping records with ``rdump``
==============================

Next we can use the ``rdump`` tool from the ``flow.record`` package to read and inspect the saved records.
By using the ``-s / --selector`` argument in ``rdump`` we can filter records and ``-f / --filter`` to specify an output format string.

For example to list all the `COMMANDS` issued by the Team Server:

.. code-block:: bash

   $ rdump c2.records.gz -s "r.command" -f "{packet_ts} {src_ip}:{src_port} | {command}"
   2021-06-15 15:09:56.371968 5.252.177.17:443 | COMMAND_SLEEP
   2021-06-15 15:10:12.291611 5.252.177.17:443 | COMMAND_INLINE_EXECUTE_OBJECT
   2021-06-15 15:10:30.437461 5.252.177.17:443 | COMMAND_SPAWN_TOKEN_X86
   2021-06-15 15:11:10.851089 5.252.177.17:443 | COMMAND_FILE_LIST
   2021-06-15 15:11:18.131182 5.252.177.17:443 | COMMAND_FILE_LIST

Example to list all the `CALLBACKS` sent by the beacon:

.. code-block:: bash

   $ rdump c2.records.gz -s "r.callback" -f "{packet_ts} {src_ip}:{src_port} | {callback}"
   2021-06-15 15:10:12.618050 10.0.0.134:52914 | CALLBACK_PENDING
   2021-06-15 15:10:33.171933 10.0.0.134:52933 | CALLBACK_PORTSCAN
   2021-06-15 15:10:40.932358 10.0.0.134:52943 | CALLBACK_PORTSCAN
   2021-06-15 15:10:50.772303 10.0.0.134:52960 | CALLBACK_PORTSCAN
   2021-06-15 15:11:11.251795 10.0.0.134:52983 | CALLBACK_PENDING

Notice that the client sent some `portscan` data back, we can inspect the portscan callback data specifically:

.. code-block:: bash

   $ rdump c2.records.gz -s "r.callback == 'CALLBACK_PORTSCAN'" -f "{packet_ts} | {data}"
   2021-06-15 15:10:33.171933 | b"(ICMP) Target '10.7.5.2' is alive. [read 8 bytes]\n(ICMP) Target '10.7.5.7' is alive. [read 8 bytes]\n\xd8\xca`\x05"
   2021-06-15 15:10:40.932358 | b"(ICMP) Target '10.7.5.134' is alive. [read 8 bytes]\nF\rEg"
   2021-06-15 15:10:50.772303 | b'10.7.5.7:445 (platform: 500 version: 10.0 name: STORMRUN-DC domain: STORMRUNCREEK)\n10.7.5.134:445 (platform: 500 version: 10.0 name: DESKTOP-X9JH6AW domain: STORMRUNCREEK)\nScanner module is complete\n\x00\x00\x00\x00'

As you can see it's quite easy and powerful to be able to inspect the beacon traffic stored as records using ``rdump``.
This is a great way to get a quick overview of the traffic and to extract the relevant data you need for further analysis.

``rdump`` has many different output formats, such as ``json`` by using the ``-j / --json`` argument:

.. code-block:: bash

   $ rdump c2.records.gz --json
   ...
   {
     "packet_ts": "2021-06-15T15:08:55.172675",
     "src_ip": "10.0.0.134",
     "src_port": 52886,
     "dst_ip": "5.252.177.17",
     "dst_port": 443,
     "raw_http": "R0VUIC9hY3Rpdml0eSBIVFRQLzEuMQ0KQWNjZXB0OiAqLyoNCkNvb2tpZToga1IvT1RGTWhDWVFwdjA5Y1hsMlI3cUVlc3BWVWZRLzhZYWhBYnMxYityRUVTYlN6Y0FjNDRSOUtsZjR6SDRHR1l4VDRkRXJ6TlFXaW1tTVc1d1FWUVNFR0ZaMzZtV2MvYmVvVVRRVUdWVXhjWldYbDB0OFdCTzEycUM2dnNtUlNWNXVRTytxeHowTGJ6MVAvd09rV3diTk0wWEY5TGhWalJyR1lTUjBKbHJjPQ0KVXNlci1BZ2VudDogTW96aWxsYS80LjAgKGNvbXBhdGlibGU7IE1TSUUgNy4wOyBXaW5kb3dzIE5UIDUuMTsgLk5FVCBDTFIgMi4wLjUwNzI3KQ0KSG9zdDogNS4yNTIuMTc3LjE3OjQ0Mw0KQ29ubmVjdGlvbjogS2VlcC1BbGl2ZQ0KQ2FjaGUtQ29udHJvbDogbm8tY2FjaGUNCg0K",
     "magic": 48879,
     "size": 92,
     "aes_rand": "+WRByIsH4Tr6CnC8e2Bt4A==",
     "ansi_cp": 58372,
     "oem_cp": 46337,
     "bid": 693615746,
     "pid": 6396,
     "port": 0,
     "flag": 4,
     "ver_major": 10,
     "ver_minor": 0,
     "ver_build": 19042,
     "ptr_x64": 0,
     "ptr_gmh": 1972243040,
     "ptr_gpa": 1972237648,
     "ip": "134.5.7.10"
   }
   ...
   {
     "packet_ts": "2021-06-15T15:09:56.371968",
     "src_ip": "5.252.177.17",
     "src_port": 443,
     "dst_ip": "10.0.0.134",
     "dst_port": 52894,
     "raw_http": "SFRUUC8xLjEgMjAwIE9LDQpEYXRlOiBUdWUsIDE1IEp1biAyMDIxIDE1OjA5OjU1IEdNVA0KQ29udGVudC1UeXBlOiBhcHBsaWNhdGlvbi9vY3RldC1zdHJlYW0NCkNvbnRlbnQtTGVuZ3RoOiA0OA0KDQ
   pQwfGgezMgqAF9/rxsjqKB10EyozvgkfWQ3V3FiGCiiJMULbS7lvEc1w2mMP7FntY=",
     "epoch": "2021-06-15T15:09:55.000000",
     "total_size": 16,
     "command": "COMMAND_SLEEP",
     "size": 8,
     "data": "AAAAZAAAAFo="
   }

We recommend to get familiar with the ``rdump`` tool and the ``flow.record`` package by going to the documentation here:
https://docs.dissect.tools/en/latest/tools/rdump.html

.. seealso::

   Other useful resources that can help by analysing Cobalt Strike traffic:

   * `Series: Cobalt Strike: Decrypting Traffic <https://blog.nviso.eu/series/cobalt-strike-decrypting-traffic/>`_ by NVISO.
   * `Analysing a malware PCAP with IcedID and Cobalt Strike traffic <https://www.netresec.com/?page=Blog&month=2021-04&post=Analysing-a-malware-PCAP-with-IcedID-and-Cobalt-Strike-traff>`_  by NETRESEC.
   * `Cobalt Strike Analysis and Tutorial: CS Metadata Encryption and Decryption <https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/>`_ by UNIT42.
   * `Open Dataset of Cobalt Strike Beacons <https://github.com/fox-it/cobaltstrike-beacon-data/>`_ by Fox-IT part of NCC Group.
