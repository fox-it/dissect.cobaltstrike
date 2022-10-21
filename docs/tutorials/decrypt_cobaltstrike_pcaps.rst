Decrypt Cobalt Strike PCAPs
---------------------------

There are some prerequisites to be able to decrypt the C2 traffic in Cobalt Strike PCAPs:

* The beacon payload of the session that can be loaded by :class:`~dissect.cobaltstrike.beacon.BeaconConfig`.

   * If not specified it will try to find a staged beacon payload in the PCAP.

* One of the following Cryptographic keys is required:

   * AES key of the beacon session (HMAC key is optional)
   * AES rand bytes of the beacon session (this can derive both the AES and HMAC key)
   * RSA Private key of the Team Server (this can decrypt the BeaconMetadata for all sessions)

* If the C2 traffic is over HTTPS/TLS then a ``SSLKEYLOGFILE`` is also required.

In this tutorial we will show how to decrypt a beacon session using a known RSA private key with the tool ``beacon-pcap``
that is installed by the ``dissect.cobaltstrike`` package.

The PCAP we are going to use is from `Malware Traffic Analysis` and can be downloaded from here:

* https://www.malware-traffic-analysis.net/2021/06/15/index.html

.. code-block:: bash

   $ wget https://www.malware-traffic-analysis.net/2021/06/15/2021-06-15-Hancitor-with-Ficker-Stealer-and-Cobalt-Strike.pcap.zip
   $ 7z x 2021-06-15-Hancitor-with-Ficker-Stealer-and-Cobalt-Strike.pcap.zip -pinfected

After the pcap is extracted we can do a preliminary analysis to find any staged beacon payloads in the pcap and extract them:

.. code-block:: bash

   $ beacon-pcap --extract-beacons 2021-06-15-Hancitor-with-Ficker-Stealer-and-Cobalt-Strike.pcap
   [+] Found <BeaconConfig ['5.252.177.17']> at b'/ZsDK', extracted beacon payload to 'beacon-ZsDK.bin'
   [+] Found <BeaconConfig ['5.252.177.17']> at b'/8mJm', extracted beacon payload to 'beacon-8mJm.bin'

We see two beacons being extracted, this most likely indicates that there are two beacon sessions in the PCAP.
If you don't provide ``--extract-beacons`` then it will try to find the (first) staged beacon payload in the PCAP and use that to decrypt the C2 traffic.

Now that the beacons are extracted, we inspect the `RSA Public Key` of the beacons using ``beacon-dump -t raw <beacon> | grep PUBKEY``.

Our goal is to find out if we can find a matching RSA **Private** Key on VirusTotal. When we query VirusTotal for the Public Key bytes we can
find that there are some malware samples but also a file called ``Cobalt Strike 4.3.zip``. 

.. figure:: ../images/vt-cobaltstrike-43-zip.png

   Leaked version of Cobalt Strike 4.3 (hash redacted)

This is a leaked version of Cobalt Strike containing a file called ``.cobaltstrike.beacon_keys``, embedded in this file is a RSA **private** key.
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

After extracting this key we have the `RSA Private Key` that we can use to decrypt beacon sessions.

.. code-block:: bash

    $ beacon-pcap -p key.pem 2021-06-15-Hancitor-with-Ficker-Stealer-and-Cobalt-Strike.pcap --beacon beacon-8mJm.bin
    <Beacon/BeaconMetadata packet_ts=2021-06-15 15:08:55.172675 src_ip=net.ipaddress('10.0.0.134') src_port=52886 dst_ip=net.ipaddress('5.252.177.17') dst_port=443 raw_http=b'GET /activity HTTP/1.1\r\nAccept: */*\r\nCookie: kR/OTFMhCYQpv09cXl2R7qEespVUfQ/8YahAbs1b+rEESbSzcAc44R9Klf4zH4GGYxT4dErzNQWimmMW5wQVQSEGFZ36mWc/beoUTQUGVUxcZWXl0t8WBO12qC6vsmRSV5uQO+qxz0Lbz1P/wOkWwbNM0XF9LhVjRrGYSR0Jlrc=\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 2.0.50727)\r\nHost: 5.252.177.17:443\r\nConnection: Keep-Alive\r\nCache-Control: no-cache\r\n\r\n' magic=48879 size=92 aes_rand=b'\xf9dA\xc8\x8b\x07\xe1:\xfa\np\xbc{`m\xe0' ansi_cp=58372 oem_cp=46337 bid=693615746 pid=6396 port=0 flag=4 ver_major=10 ver_minor=0 ver_build=19042 ptr_x64=0 ptr_gmh=1972243040 ptr_gpa=1972237648 ip=net.ipaddress('134.5.7.10') info=b'DESKTOP-X9JH6AW\ttabitha.gomez\tsvchost.exe'>
    <Beacon/TaskPacket packet_ts=2021-06-15 15:09:56.371968 src_ip=net.ipaddress('5.252.177.17') src_port=443 dst_ip=net.ipaddress('10.0.0.134') dst_port=52894 raw_http=b'HTTP/1.1 200 OK\r\nDate: Tue, 15 Jun 2021 15:09:55 GMT\r\nContent-Type: application/octet-stream\r\nContent-Length: 48\r\n\r\nP\xc1\xf1\xa0{3 \xa8\x01}\xfe\xbcl\x8e\xa2\x81\xd7A2\xa3;\xe0\x91\xf5\x90\xdd]\xc5\x88`\xa2\x88\x93\x14-\xb4\xbb\x96\xf1\x1c\xd7\r\xa60\xfe\xc5\x9e\xd6' epoch=2021-06-15 15:09:55 total_size=16 command='COMMAND_SLEEP' size=8 data=b'\x00\x00\x00d\x00\x00\x00Z'>

We specify a beacon specifically as there are two beacon sessions in this pcap but they have slightly different urls.
If you want to decrypt the other session just pass the other beacon as the parameter using ``--beacon``.

By default ``beacon-pcap`` will output decrypted C2 traffic to stdout as `flow.record` format.
You can redirect the records to a file, or write them to a file using ``-w / --writer``, or even pipe it directly to ``rdump``.

Example of writing the decrypted C2 records to ``c2.records.gz``:

.. code-block:: bash

   $ beacon-pcap -w c2.records.gz -p key.pem 2021-06-15-Hancitor-with-Ficker-Stealer-and-Cobalt-Strike.pcap --beacon beacon-8mJm.bin

Next we can use the ``rdump`` tool from the ``flow.record`` package to read and inspect the saved records.
For example to list all the `COMMANDS` issued by the Team Server:

.. code-block:: bash

   $ rdump c2.records.gz -s "r.command" -f "{packet_ts} {src_ip}:{src_port} | {command}"
   2021-06-15 15:09:56.371968 5.252.177.17:443 | COMMAND_SLEEP
   2021-06-15 15:10:12.291611 5.252.177.17:443 | COMMAND_INLINE_EXECUTE_OBJECT
   2021-06-15 15:10:30.437461 5.252.177.17:443 | COMMAND_SPAWN_TOKEN_X86
   2021-06-15 15:11:10.851089 5.252.177.17:443 | COMMAND_FILE_LIST
   2021-06-15 15:11:18.131182 5.252.177.17:443 | COMMAND_FILE_LIST

Example to list all the CALLBACKs sent by the beacon:

.. code-block:: bash

   $ rdump c2.records.gz -s "r.callback" -f "{packet_ts} {src_ip}:{src_port} | {callback}"
   2021-06-15 15:10:12.618050 10.0.0.134:52914 | CALLBACK_PENDING
   2021-06-15 15:10:33.171933 10.0.0.134:52933 | CALLBACK_PORTSCAN
   2021-06-15 15:10:40.932358 10.0.0.134:52943 | CALLBACK_PORTSCAN
   2021-06-15 15:10:50.772303 10.0.0.134:52960 | CALLBACK_PORTSCAN
   2021-06-15 15:11:11.251795 10.0.0.134:52983 | CALLBACK_PENDING

Or dump the portscan callback data specifcally:

.. code-block:: bash

   $ rdump c2.records.gz -s "r.callback == 'CALLBACK_PORTSCAN'" -f "{packet_ts} | {data}"
   2021-06-15 15:10:33.171933 | b"(ICMP) Target '10.7.5.2' is alive. [read 8 bytes]\n(ICMP) Target '10.7.5.7' is alive. [read 8 bytes]\n\xd8\xca`\x05"
   2021-06-15 15:10:40.932358 | b"(ICMP) Target '10.7.5.134' is alive. [read 8 bytes]\nF\rEg"
   2021-06-15 15:10:50.772303 | b'10.7.5.7:445 (platform: 500 version: 10.0 name: STORMRUN-DC domain: STORMRUNCREEK)\n10.7.5.134:445 (platform: 500 version: 10.0 name: DESKTOP-X9JH6AW domain: STORMRUNCREEK)\nScanner module is complete\n\x00\x00\x00\x00'

As you can see it's quite easy and powerful to be able to inspect the beacon traffic stored as records using ``rdump``.
This is a great way to get a quick overview of the traffic and to extract the relevant data you need for further analysis.

We recommend to get familiar with the ``rdump`` tool and the ``flow.record`` package by going to the documentation here:
https://docs.dissect.tools/en/latest/tools/rdump.html

..  seealso::

   Other useful resources that can help by analysing Cobalt Strike traffic:

   * `Series: Cobalt Strike: Decrypting Traffic <https://blog.nviso.eu/series/cobalt-strike-decrypting-traffic/>`_ by NVISO.
   * `Analysing a malware PCAP with IcedID and Cobalt Strike traffic <https://www.netresec.com/?page=Blog&month=2021-04&post=Analysing-a-malware-PCAP-with-IcedID-and-Cobalt-Strike-traff>`_  by NETRESEC.
   * `Cobalt Strike Analysis and Tutorial: CS Metadata Encryption and Decryption <https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/>`_ by UNIT42.
