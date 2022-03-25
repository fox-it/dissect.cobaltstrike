beacon-xordecode
================

The command ``beacon-xordecode`` can be used to decode a XorEncoded Cobalt Strike beacon. Not to be confused with the single-byte XOR key that is used to encrypt the Beacon Configuration.

.. code-block:: bash

   $ beacon-xordecode <beacon-file> | xxd

If the command is not in your path, you can also use run the command using the following Python module:

.. code-block:: bash

   $ python -m dissect.cobaltstrike.xordecode --help

Nonce offset
------------

A XorEncoded beacon payload consists of the xordecode shellcode stub, the initial `nonce`, the size and then the XorEncoded payload::

        +--------------------------+---------------+----------------------+--------------------+
        | xordecode shellcode stub | nonce (dword) | payload size (dword) | xorencoded payload |
        +--------------------------+---------------+----------------------+--------------------+

To properly decode the XorEncoded payload, the `nonce` offset must be known. The following two different methods are used to determine the `nonce` offset / start of XorEncoded payload:

 - Determine `nonce` based on file size, the decoded ``size`` field is the size of the XorEncoded payload. If it matches it is used as a candidate.
 - Determine `nonce` offset based on the end marker of the xordecode shellcode stub.

MZ header
---------

After the `nonce` candidates have been found it will try to find which of the candidates is the correct one. The MZ header is used to determine the correct candidate.
If no MZ header can be found in the payload it will return an error.

You can still use the ``-n`` or ``--nonce-offset`` option to manually specify the nonce offset, this will override the automatic nonce and MZ detection.

.. sphinx_argparse_cli::
  :module: dissect.cobaltstrike.xordecode
  :func: build_parser
  :prog: beacon-xordecode
