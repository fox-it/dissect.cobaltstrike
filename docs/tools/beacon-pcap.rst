beacon-pcap
===========

The command ``beacon-pcap`` can be used to parse PCAP files containing Cobalt Strike C2 traffic.
The AES key of the beacon session or RSA Private key of the Team Server is required to decrypt the traffic.

.. tip::

    If you enable ``-v / --verbose`` logging, and you have the ``rich`` module installed. It will automatically
    use `rich <https://rich.readthedocs.io/en/stable/>`_ to render the console logging which can be easier on the eyes.

The beacon config or payload can be specified using the ``-b / --beacon`` flag, if not specified it tries to
find one in the PCAP by checking for any staged beacon payloads. It will will always use the first one it finds in
the PCAP. If there are multiple staged beacons in the PCAP, you can extract them first using ``-e / --extract-beacons``
and specify the one you want to use with ``--beacon``.

To ensure you have all the dependencies for ``beacon-pcap`` you can use the following pip command:

.. code-block:: bash

   $ pip install -e dissect.cobaltstrike[pcap]

Example usage for if you have the RSA private key:

.. code-block:: bash

   $ beacon-pcap --private-key privkey.der traffic.pcap

This will read ``traffic.pcap`` and use the RSA Private key ``privkey.der`` for decrypting Beacon Metadata and C2 Packets.
As no beacon is specified, it will try to find a staged beacon payload in the PCAP.

By default all the decrypted C2 packets are written as `flow.records`` records to `stdout`.
The output can be redirected to a file using the ``-w / --writer`` argument, example:

.. code-block:: bash

   $ beacon-pcap -v -p privkey.der -w beacon-c2.records.gz traffic.pcap

This will write the decrypted C2 packets to ``beacon-c2.records.gz`` instead of `stdout`.
The file can then be dumped using the tool ``rdump`` which is part of the `flow.record`_ package and is installed as a dependency.

.. code-block:: bash

   $ rdump beacon-c2.records.gz

.. _flow.record: https://github.com/fox-it/flow.record

If the command is not in your path, you can also run the command using the following Python module:

.. code-block:: bash

   $ python -m dissect.cobaltstrike.pcap --help

.. sphinx_argparse_cli::
  :module: dissect.cobaltstrike.pcap
  :func: main
  :hook:
  :prog: beacon-pcap
