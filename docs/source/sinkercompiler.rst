Sinker Compiler
===============

The Sinker Compiler can be used to amalgamate multiple Sinker DSL files into one file. It can also be used to generate a ``.def`` header file that can be included in C++ source code with useful macros and boilerplate code for the Sinker Runtime Library.

The compiler accepts a list of positional input source file paths that will be evaluated in the order the arguments are specified. The ``-o <amalgamated_file_path>`` option can be used to specify where the output file should go. If this option is missing, then no ``.skr`` file will be output. Finally, the ``-d <def_file_path>`` can be used to specify where the ``.def`` file should go. If this option is missing, then no ``.def`` file will be output.

``.def``
--------

For the following ``.skr`` file

.. code-block::

    module crackme;
    variant crackme, v1_0_0, "deadbeefdeadbeefdeadbeefdeadbeef"
    symbol check_flag, "bool(*)(char const * flag)";
    tag crackme::check_flag, hook;
    address crackme::check_flag, v1_0_0, @0xc0dec0de;

The ``.def`` file will contain the following:

.. code-block:: cpp

    #ifndef SINKER_MODULE
    #define SINKER_MODULE(module_name)
    #endif
    #ifndef SINKER_SYMBOL
    #define SINKER_SYMBOL(module_name, symbol_name, symbol_type)
    #endif
    #ifndef SINKER_TAG_hook_SYMBOL
    #define SINKER_TAG_hook_SYMBOL(module_name, symbol_name, symbol_type)
    #endif

    #ifndef SINKER_crackme_SYMBOL
    #define SINKER_crackme_SYMBOL(symbol_name, symbol_type)
    #endif
    #ifndef SINKER_crackme_TAG_hook_SYMBOL
    #define SINKER_crackme_TAG_hook_SYMBOL(symbol_name, symbol_type)
    #endif
    SINKER_MODULE(crackme)
    SINKER_SYMBOL(crackme, check_flag, bool(*)(char const * flag))
    SINKER_TAG_hook_SYMBOL(crackme, check_flag, bool(*)(char const * flag))
    SINKER_crackme_SYMBOL(check_flag, bool(*)(char const * flag))
    SINKER_crackme_TAG_hook_SYMBOL(check_flag, bool(*)(char const * flag))
    #undef SINKER_crackme_TAG_hook_SYMBOL
    #undef SINKER_crackme_SYMBOL

    #undef SINKER_TAG_hook_SYMBOL
    #undef SINKER_MODULE
    #undef SINKER_SYMBOL

and it can be used like the following simple example:

.. code-block:: cpp

    #include <stdio.h>
    void print_modules() {
    #define SINKER_MODULE(module_name) \
        puts(#module_name);
    #include "a.def"
    }

    void print_symbols() {
    #define SINKER_SYMBOL(module_name, symbol_name, symbol_type) \
        puts(#symbol_name);
    #include "a.def"
    }

The macros can be redefined and the ``.def`` can be included as many times as necessary.
