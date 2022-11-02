beacon-client
=============

The command ``beacon-client`` can be used to connect to a Cobalt Strike Team Server given a beacon config or payload.
It will read the beacon settings so it can communicate with the C2 server, and then it will start do check-ins and
retrieve Tasks like a real beacon.

.. tip::

    If you enable ``-v / --verbose`` logging, and you have the ``rich`` module installed. It will automatically
    use `rich <https://rich.readthedocs.io/en/stable/>`_ to render the console logging which can be easier on the eyes.

The implementation of the client in ``beacon-client`` is observing only, meaning it does not implement any of the
beacon functionality such as executing commands or listing files and does not send any Callback data to the Team Server.

If you want to know how to implement your own custom beacon client that can respond to tasks, please refer to
this :doc:`tutorial <../tutorials/minimal_beacon_client>`.

The ``--writer`` parameter of ``beacon-client`` allows you to log the retrieved `beacon tasks` to a file.
This can be useful for debugging or logging of tasks that are being sent.
The output is written as `flow.record` records and can be dumped using the tool ``rdump`` which is part of
the `flow.record`_ package and is installed as a dependency.

To ensure you have all the dependencies for ``beacon-client`` you can use the following pip command:

.. code-block:: bash

   $ pip install -e dissect.cobaltstrike[c2]

Here is an example usage of connecting to a Team Server with custom Beacon metadata, we choose a fixed beacon id so we
can connect to it again later without creating a new beacon session at the Team Server:

.. code-block:: bash

   $ beacon-client beacon.bin -vi 1234 --user "wing" --computer "safecomputer" -w c2.records.gz

* This will launch the beacon-client using ``beacon.bin`` as the BeaconConfig.
* The ``-v`` flag will enable verbose logging. (recommend to see what is going on)
* The ``-i`` flag will set the Beacon ID to ``1234``.
* The ``--user`` and ``--computer`` arguments are used to set the username and computer name in the Beacon Metadata.
* and ``-w`` or ``--writer`` writes decrypted C2 packets such as Tasks and Callback packets to the file ``c2.records.gz``.

There are many more options that can be overridden, by default most settings are randomized. To see all the options run
it with ``--help`` and is also documented here: :ref:`CLI-interface`.

Dumping saved records
---------------------
The contents of ``c2.records.gz`` can then be dumped using the ``rdump`` (record dump) tool:

.. code-block:: bash

   $ rdump c2.records.gz

For more advanced usage of ``rdump`` use ``--help`` or see the documentation for `flow.record`_.

.. _flow.record: https://github.com/fox-it/flow.record

If ``beacon-client`` is not in your path, you can also run the command using the following Python module:

.. code-block:: bash

   $ python -m dissect.cobaltstrike.client --help

.. _CLI-interface:
.. sphinx_argparse_cli::
  :module: dissect.cobaltstrike.client
  :func: main
  :hook:
  :prog: beacon-client
