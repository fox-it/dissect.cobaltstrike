beacon-dump
===========

You can use the command ``beacon-dump`` to dump configuration from Cobalt Strike beacon paylaods.

If the command is not in your path, you can also use run the command using the following Python module:

.. code-block:: bash

   $ python -m dissect.cobaltstrike.beacon --help

XOR keys
--------
The beacon configuration is usually obfuscated using a single-byte XOR key. ``beacon-dump`` automatically tries all the default xor keys (``0x69`` and ``0x2e``).

In case a beacon uses a non default XOR key you can specify the ``-a`` or ``--all-xor-keys`` argument to check all possible single byte XOR keys.
Note that this option is not recommended for large payloads such as memory dumps.

You can also use the ``-x`` or ``--xorkey`` option to specify a known XOR key or a set of keys by repeating the argument:

.. code-block:: bash

   $ beacon-dump -x 0xAC -x 0xCE -x 0x55 -x 0xED <beacon-file>

Output format
-------------

The output format can be specified using the ``-f`` or ``--format`` option. The following formats are supported:

   - ``normal``: output the beacon configuration in a human readable format of key value pairs (default)
   - ``dumpstruct``: output the beacon settings using ``cstruct.dumpstruct``
   - ``c2profile``: output the beacon configuration as a malleable C2 profile
   - ``raw``: output the raw beacon configuration

.. sphinx_argparse_cli::
  :module: dissect.cobaltstrike.beacon
  :func: build_parser
  :prog: beacon-dump
