C2Profile grammar
==================

:py:mod:`dissect.cobaltstrike` utilizes the `Lark`_ parser for parsing and generating Cobalt Strike Malleable C2 Profiles.

The `Lark grammar`_ file to parse the `Profile Language` is defined in ``c2profile.lark`` and listed below for reference.

.. note::

   Currently, the grammar implementation is pretty naive and could be improved upon.
   For example, the values are all `STRING` but could benefit from other types as well.

.. _Lark: https://github.com/lark-parser/lark
.. _Lark grammar: https://lark-parser.readthedocs.io/en/latest/grammar.html

.. literalinclude:: ../dissect/cobaltstrike/c2profile.lark
   :language: ruby
