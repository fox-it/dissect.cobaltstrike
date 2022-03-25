c2profile-dump
==============

The command ``c2profile-dump`` can be used to parse and dump Malleable C2 profiles. The command is mainly useful for debugging the parsed AST tree. Using the library directly is more useful for extracting information using Python.

.. code-block:: bash

    $ c2profile-dump /path/to/profile.c2

To load from a beacon and dump as properties:

.. code-block:: bash

    $ c2profile-dump -b <beacon> -t properties

If the command is not in your path, you can also use run the command using the following Python module:

.. code-block:: bash

   $ python -m dissect.cobaltstrike.c2profile --help

.. sphinx_argparse_cli::
  :module: dissect.cobaltstrike.c2profile
  :func: build_parser
  :prog: c2profile-dump


