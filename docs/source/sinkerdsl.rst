Sinker DSL
==========

Sinker DSL can be written out-of-line in a separate file with the ``.skr`` extension. It can also be written inline alongside source code in the same file where lines to be evaluated as Sinker DSL begin with ``//$``; the "$" is for the "S" in "Sinker", I'm too clever for my own good. Only whitespace is allowed before this token on a line, not unlike the C preprocessor. Any file with an extension other than ``.skr`` is assumed to be a source code file.

Language Elements
-----------------

Directive
^^^^^^^^^

Every Sinker DSL statement starts with a :ref:`directive <Directives>`.

Identifier
^^^^^^^^^^

An identifier is a token matching the Regex ``[a-zA-Z_$][a-zA-Z0-9_$]*`` that does not already have a meaning in Sinker DSL.

Identifier Set
^^^^^^^^^^^^^^

A non-empty comma-separated list of identifiers surrounded by square brackets or an asterisk surrounded by square brackets, a wildcard representing all variants.

Integer Literal
^^^^^^^^^^^^^^^

An integer literal is a decimal, hexadecimal, prefixed with ``0x``, octal, prefixed with ``0``, or binary, prefixed with ``0b``, integer.

String Literal
^^^^^^^^^^^^^^

A string literal is any sequence of characters enclosed in quotes. There are no escape sequences. Adjoining string literals will be treated as a single string literal i.e. ``"sink" "er ro" "cks"`` is equivalent to ``"sinker rocks"``. This can be used to split a string literal across multiple lines.

Boolean Literal
^^^^^^^^^^^^^^^

A boolean literal is either ``true`` or ``false``.

Expression
^^^^^^^^^^

An expression is written in the `Sinker DSL Expression Language`_.

Comments
^^^^^^^^

Any characters between the sequence ``//`` and the end of a line will be ignored in Sinker DSL.

Directives
----------

Module
^^^^^^

A module corresponds to a target PE file, ``.exe`` or ``.dll``, loaded into the injected process's memory space. The ``lpModuleName`` is the argument passed to ``GetModuleHandle``; exclude this argument to pass ``NULL`` to ``GetModuleHandle``.

| ``module <module_name:identifier>, <lpModuleName:string>;``
| ``module <module_name:identifier>;``

Variant
^^^^^^^

A variant corresponds to a known distribution of a target PE file, identified by its SHA256 hash. This makes it easier to provide known addresses for each binary variant. If a PE file does not match any of the known hashes, it will not have a variant name. The SHA256 hash of a file can be obtained using the ``certUtil -hashfile C:\file.exe SHA256`` command on Windows.

``variant <module_name:identifier>, <variant_name:identifier>, <sha256_hash:string>;``

Symbol
^^^^^^

A symbol is a variant-agnostic representation of an address in a binary. A symbol can be pretty much anything: function, vtable, global data, etc. As you will soon see, Sinker is very versatile.

``symbol <module_name:identifier>::<symbol_name:identifier>, <symbol_type:string>;``

Address
^^^^^^^

An address provides instructions on how to calculate the address for a symbol based on its variant. These calculations are done using the `Sinker DSL Expression Language`_.

Address directives for each symbol are evaluated in the order they are declared. For each address directive where a ``variant_name`` in the set matches the current module's variant or the wildcard is used, the expression is evaluated. The first expression that is resolved will be the calculated address of the symbol. If all expressions are unresolved, the symbol is unresolved.

It is generally advisable to declare at least one address declaration where the variant is a wildcard. This is so that if a module does not have a variant name, due to no hashes matching or lack of variant declarations, there is still an opportunity to resolve an address for the symbol.

``address <module_name:identifier>::<symbol_name:identifier>, <variant_names:identifier_set>, <expression:expression>;``

Set
^^^

A module or symbol can have arbitrary user-defined attributes associated with them. This can be used, for example, to mark a symbol as "required" and check at runtime if all "required" symbols have been resolved.

| ``set <module_name:identifier>, <attribute_name:identifier>, <value:boolean|integer|string>;``
| ``set <module_name:identifier>::<symbol_name:identifier>, <attribute_name:identifier>, <value:boolean|integer|string>;``

Tag
^^^

Modules or symbols can be grouped by arbitrary user-defined tags. These can be used, for example, to mark symbols as "hookable" and generate code to hook them at compile-time. Tags cannot have values and are accessible at compile-time, unlike attributes. Tags and attributes can be combined to generate code for all "hookable" symbols at compile time and then only hook the "enabled" symbols at runtime for example.

| ``tag <module_name:identifier>, <tag_name:identifier>;``
| ``tag <module_name:identifier>::<symbol_name:identifier>, <tag_name:identifier>;``

Sinker DSL Expression Language
------------------------------

Any operation with an unresolved operand will evaluate as unresolved; or, in other words, if any part of an expression is unresolved then the whole expression is unresolved.

Integer Literal
^^^^^^^^^^^^^^^

``integer``

An integer literal will be evaluated as its numeric value.

Identifier
^^^^^^^^^^

``module_name``

A module's name will be evaluated as its relocated base address or unresolved if the module has not been concretized.

``module_name::symbol_name``

A symbol's name will be evaluated as its calculated address or unresolved.

GetProcAddress
^^^^^^^^^^^^^^

``!module_name::lpProcName``

Use ``GetProcAddress`` to find ``lpProcName`` in ``module_name``. If found this evaluates to the returned address, otherwise unresolved.

Pattern Match
^^^^^^^^^^^^^

| ``{}``
| ``{ needle }``
| ``{ needle : mask }``
| ``[filter]{ needle }``
| ``[filter]{ needle : mask }``
| ``[filter]{}``

Inspired by |frida|_ which is in turn inspired by |radare2|_.

..
    https://stackoverflow.com/a/4836544/3997768

.. |frida| replace:: Frida's JavaScript API's ``Memory.scan``
.. _frida: https://frida.re/docs/javascript-api/#memory

.. |radare2| replace:: Radare2's ``/x`` command
.. _radare2: https://book.rada.re/search_bytes/intro.html

Filter
""""""

Filters are optional. If a filter is specified and no needle is specified, then the expression will evaluate to the first searched address matching the filter. This can be used to get the address of a module's text segment by filtering for it and not using a needle for example. The following filters are supported:

* No filter. Search all readable pages.
* ``module_name`` search all sections in the specified module.
* ``module_name::"section_name"`` search the section in the specified module.

A comma separated list of filters may be used. If the module in a filter has not been concretized then that filter is skipped. If none of them are then the expression is unresolved.

Needle
""""""

Searches for the first occurrence of the pattern in the module text segment and evaluates to the address of the first byte of the matched pattern. If no match is found, the pattern match evaluates to unresolved. A needle contains a series of the following:

* ``XX`` a hexadecimal byte value with no prefix. The search byte must equal this value.
* ``??`` the search byte may be equal to any value.
* ``X?`` lower nibble wildcard, the high nibble of the search byte must equal the high nibble of this value.
* ``?X`` upper nibble wildcard, the low nibble of the search byte must equal the low nibble of this value.
* ``"string"`` a string literal. Insert the ASCII bytes of the string into the needle.
* ``&`` the pattern match expression will evaluate to the address of byte following this if specified. Can only be used once. This can be used to match a whole jump instruction but evaluate as the address of the operand of the jump.

Mask
""""

The mask is optional. The needle and mask must be the same length. Wildcards in the needle cannot be mixed with a mask.

* ``XX`` a hexadecimal byte value with no prefix. The needle and haystack will be AND'd with this value.

Operations
^^^^^^^^^^

Parentheses
"""""""""""

``(expression)``

Parentheses can be used to change the sequence of evaluation.

Mathematical Operations
"""""""""""""""""""""""

| ``expression + expression``
| ``expression - expression``
| ``expression * expression``
| ``expression / expression`` (Integer Division)
| ``expression % expression`` (Modulo)

Mathematical operations are applied as if the expressions are integers; there is no pointer arithmetic in Sinker DSL.

Indirection (dereference)
"""""""""""""""""""""""""

``*expression``

The expression to be dereferenced will be treated as a ``void**``, the result of the dereference operation will be an address, ``void*``. System endianness will be used. If dereferencing the expression causes an access violation, the expression will evaluate to unresolved. From this definition of the Indirection operator, an easy way to raise an unresolved value arises, ``*0``; I'm not sure why you would want to do this, but hey I can't stop you.

Array Subscripting
""""""""""""""""""

``expression1[expression2]``

Equivalent to ``*(expression1 + expression2 * sizeof(void*))`` where ``sizeof(void*)`` is the size, in bytes, of a pointer; note that ``sizeof(void*)`` is purely demonstrative of the behavior of the operation and not valid Sinker DSL.

Pointer Path
""""""""""""

``expression1->expression2``

| Equivalent to ``*expression1 + expression2``. This can be chained together multiple times for a LiveSplit Auto Splitter style pointer path i.e. ``0xDEADBEEF->0xABCD->0x1234`` will read an address at ``0xDEADBEEF`` then add ``0xABCD`` and read an address there, finally ``0x1234`` is added to that address.
| Inspired by `LiveSplit Auto Splitter Pointer Paths <https://github.com/LiveSplit/LiveSplit.AutoSplitters#pointer-paths>`_.

Relocate
""""""""

``@expression``

This will subtract the symbol's module's preferred base address from the expression and then add the symbol's module's relocated base address to the expression.

Operator Precedence
"""""""""""""""""""

Adapted from `C Operator Precedence <https://en.cppreference.com/w/c/language/operator_precedence>`_.

+------------+----------------+-----------------------------+---------------+
| Precedence | Operator       | Description                 | Associativity |
+============+================+=============================+===============+
| 1          | | ``[]``       | | Array Subscripting        | Left-to-right |
|            | | ``->``       | | Pointer Path              |               |
+------------+----------------+-----------------------------+---------------+
| 2          | | ``!``        | | GetProcAddress            | Right-to-left |
|            | | ``*``        | | Indirection (dereference) |               |
|            | | ``@``        | | Relocate                  |               |
+------------+----------------+-----------------------------+---------------+
| 3          | | ``*``        | | Multiplication            | Left-to-right |
|            | | ``/``        | | Integer Division          |               |
|            | | ``%``        | | Modulo                    |               |
+------------+----------------+-----------------------------+---------------+
| 4          | | ``+``        | | Addition                  | Left-to-right |
|            | | ``-``        | | Subtraction               |               |
+------------+----------------+-----------------------------+---------------+
