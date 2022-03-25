.. dissect.cobaltstrike documentation master file, created by
   sphinx-quickstart on Mon Feb 21 17:43:02 2022.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

dissect.cobaltstrike documentation
==================================

Welcome! This is the official documentation for ``dissect.cobaltstrike``.

*dissect.cobaltstrike* is a Python library for dissecting and parsing Cobalt Strike
related data such as beacon payloads and Malleable C2 Profiles.

Source code can be found here:

- https://github.com/fox-it/dissect.cobaltstrike

.. note::
   *dissect.cobaltstrike* is released under the :doc:`MIT license <license>`.

.. toctree::
   :maxdepth: 2
   :caption: Overview

   installation
   examples

.. toctree::
   :maxdepth: 1
   :titlesonly:
   :caption: Tools
   :glob:

   tools/*

.. toctree::
   :maxdepth: 2
   :caption: Reference

   API reference <autoapi/dissect/cobaltstrike/index>
   structures/index
   c2profile-grammar


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
