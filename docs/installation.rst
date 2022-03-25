Installation
============

The easiest way to install ``dissesct.cobaltstrike`` is to use **pip**:

.. code-block:: bash

    $ pip install dissect.cobaltstrike

Python 3.6 or higher is required and it has the following dependencies:

 * dissect.cstruct_ - for structure parsing
 * lark_ - for parsing malleable c2 profiles

.. _dissect.cstruct: https://github.com/fox-it/dissect.cstruct
.. _lark: https://github.com/lark-parser/lark

Installing from source
----------------------

If you want to install ``dissect.cobaltstrike`` from source, you can use the following steps:

.. code-block:: bash

     $ git clone https://github.com/fox-it/dissect.cobaltstrike.git
     $ cd dissect.cobaltstrike
     $ pip install --editable .

Using a virtual environment is recommended. Using the ``--editable`` flag ensures that any changes you make to the source code directly affects the installed package.

Running tests
-------------

The test suite uses ``pytest`` and using ``tox`` is the recommended way to run the test suite:

.. code-block:: shell

     $ pip install tox
     $ tox

This wil run tests on both Python 3 and PyPy3. To limit to Python 3 only, run:

.. code-block:: shell

     $ tox -e py3

You can also specify custom arguments to ``pytest`` by appending the arguments after ``--`` (two dashes), e.g. to only
run tests with `checksum8` in the name including verbose and stdout logging:

.. code-block:: shell

     $ tox -e py3 -- -vs -k checksum8

.. note::
   The test suite contains zipped beacon payloads that are used as test fixtures and can be unzipped during some tests.
   Running the test suite on Windows could trigger Windows Defender or your Antivirus.

Linting
-------

For linting (black and flake8):

.. code-block:: shell

     $ tox -e lint

Documentation
-------------

To generate the documentation locally (sphinx):

.. code-block:: shell

     $ tox -e docs

