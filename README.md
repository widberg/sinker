# Sinker

Instrument Windows binaries hook, line, and sinker at runtime with this convenient all-in-one hook specification and installation suite. [Sinker DSL](#sinker-dsl) is a simple domain-specific language for specifying addresses in a loaded module programmatically. The [Sinker Compiler](#sinker-compiler) makes it easy to amalgamate many Sinker DSL files and produce `.def` headers for easy use of the Sinker Runtime Library from C++. The [Sinker Runtime Library](#sinker-runtime-library) installs the specified hooks into a module at runtime.

This project spawned from my desire for a more expressive way of declaring addresses across variants of modules. My goal for this suite is to target the lowest common denominator of functionality required to instrument different binaries. That is to say, if you need some very specific functionality for a binary you are working with, implement it on top of Sinker, rather than complicating Sinker with additional features that are only useful in specific cases. The restriction to Windows and C++ is rather arbitrary, that's the platform and language I intend to use this suite for. It should be possible to add support for additional platforms and/or languages, albeit not trivial.

## Sinker DSL

Sinker DSL can be written out-of-line in a separate file with the `.skr` extension. It can also be written inline alongside source code in the same file where lines to be evaluated as Sinker DSL begin with `//$`; the "$" is for the "S" in "Sinker", I'm too clever for my own good. Only whitespace is allowed before this token on a line, not unlike the C preprocessor. Any file with an extension other than `.skr` is assumed to be a source code file.

### Types

#### Directive

Every Sinker DSL statement starts with a [Directive](#Directives).

#### Identifier

An identifier is a token matching the Regex `[a-zA-Z_$][a-zA-Z0-9_$]*` that does not already have a meaning in Sinker DSL.

#### Identifier Set

A non-empty comma-separated list of identifiers surrounded by square brackets or an asterisk surrounded by square brackets, a wildcard representing all variants.

#### Integer Literal

An integer literal is a decimal, hexadecimal, prefixed with `0x`, octal, prefixed with `0`, or binary, prefixed with `0b`, integer.

#### String Literal

A string literal is any sequence of characters enclosed in quotes. There are no escape sequences. String literals may span across multiple lines.

#### Boolean Literal

A boolean literal is either `true` or `false`.

#### Expression

An expression is a sequence of [Sinker DSL Operations](#Operations).

### Comments

Any characters between the sequence `//` and the end of a line will be ignored in Sinker DSL.

### Directives

#### Module

A module corresponds to a target PE file, `.exe` or `.dll`, loaded into the injected process's memory space. The `lpModuleName` is the argument passed to `GetModuleHandle`; exclude this argument to pass `NULL` to `GetModuleHandle`.

`module <module_name:identifier>, <lpModuleName:string>;`  
`module <module_name:identifier>;`

#### Variant

A variant corresponds to a known distribution of a target PE file, identified by its hash. This makes it easier to provide known addresses for each binary variant. If a PE file does not match any of the known hashes, it will not have a variant name. The SHA256 hash of a file can be obtained using the `certUtil -hashfile C:\file.exe SHA256` command on Windows.

`variant <module_name:identifier>, <variant_name:identifier>, <sha256_hash:string>;`

#### Symbol

A symbol is a variant-agnostic representation of an address in a binary. A symbol can be pretty much anything: function, vtable, global data, etc. As you will soon see, Sinker is very versatile.

`symbol <module_name:identifier>::<symbol_name:identifier>, <symbol_type:string>;`

#### Address

An address provides instructions on how to calculate the address for a symbol based on its variant. These calculations are done using the set of [Sinker DSL Operations](#Operations).

Address directives for each symbol are evaluated in the order they are declared. For each address directive where a `variant_name` in the set matches the current module's variant or the wildcard is used, the expression is evaluated. The first expression that is resolved will be the calculated address of the symbol. If all expressions are unresolved, the symbol is unresolved.

It is generally advisable to declare at least one address declaration where the variant is excluded. This is so that if a module does not have a variant name, due to no hashes matching or lack of variant declarations, there is still an opportunity to resolve an address for the symbol.

`address <module_name:identifier>::<symbol_name:identifier>, <variant_names:identifier_set>, <expression:expression>;`

#### Set

A module or symbol can have arbitrary user-defined attributes associated with them. This can be used, for example, to mark a symbol as "required" and check at runtime if all "required" symbols have been resolved.

`set <module_name:identifier>, <attribute_name:identifier>, <value:boolean|integer|string>;`  
`set <module_name:identifier>::<symbol_name:identifier>, <attribute_name:identifier>, <value:boolean|integer|string>;`

#### Tag

Modules or symbols can be grouped by arbitrary user-defined tags. These can be used, for example, to mark symbols as "hookable" and generate code to hook them at compile-time. Tags cannot have values and are accessible at compile-time, unlike attributes. Tags and attributes can be combined to generate code for all "hookable" symbols at compile time and then only hook the "enabled" symbols at runtime for example.

`tag <module_name:identifier>, <tag_name:identifier>;`  
`tag <module_name:identifier>::<symbol_name:identifier>, <tag_name:identifier>;`

### Operations

Any operation with an unresolved operand will evaluate as unresolved; or, in other words, if any part of an expression is unresolved then the whole expression is unresolved.

#### Parentheses

`(expression)`

Parentheses can be used to change the sequence of evaluation.

#### Integer Literal

`integer`

An integer literal will be evaluated as its numeric value.

#### Identifier

`module_name`

A module's name will be evaluated as its relocated base address or unresolved.

`module_name::symbol_name`

A symbol's name will be evaluated as its calculated address or unresolved.

#### GetProcAddress

`!module_name::lpProcName`

Use `GetProcAddress` to find `lpProcName` in `module_name`. If found this evaluates to the returned address, otherwise unresolved.

#### Mathematical Operations

`expression + expression`  
`expression - expression`  
`expression * expression`

Mathematical operations are applied as if the expressions are integers; there is no pointer arithmetic in Sinker DSL.

#### Pattern Match

`{ byte_pattern ... }`

Searches for the first occurrence of the pattern in the module text segment and evaluates to the address of the first byte of the matched pattern. If no match is found, the pattern match evaluates to unresolved. A `byte_pattern` is described as follows:  
`XX` where `XX` is a hexadecimal byte value with no prefix. The search byte must equal this value.  
`??` the search byte may be equal to any value.  
Arbitrarily masked matching may be added in the future.  
Inspired by [Frida's JavaScript API's Memory.scan](https://frida.re/docs/javascript-api/#memory).

#### Indirection (dereference)

`*expression`

The expression to be dereferenced will be treated as a `void**`, the result of the dereference operation will be an address, `void*`. System endianness will be used.

#### Array Subscripting

`expression1[expression2]`

Equivalent to `*(expression1 + expression2 * sizeof(void*))` where `sizeof(void*)` is the size, in bytes, of a pointer; note that `sizeof(void*)` is purely demonstrative of the behavior of the operation and not valid Sinker DSL.

#### Relocate

`@expression`

This will subtract the symbol's module's preferred base address from the expression and then add the symbol's module's relocated base address to the expression.

#### Null Check

`?expression`

If the value of the expression is `NULL` then this evaluates to unresolved, otherwise, this evaluates to the resolved value of the expression. Note that this operator by itself does not dereference anything. This is a good way to stop evaluating an expression before dereferencing a null pointer when that is a possibility. From this definition of the Null Check operator, an easy way to raise an unresolved value arises, `?0`; I'm not sure why you would want to do this, but hey I can't stop you.

#### Operator Precedence

Adapted from [C Operator Precedence](https://en.cppreference.com/w/c/language/operator_precedence).

| Precedence | Operator | Description | Associativity |
|------------|----------|-------------|---------------|
| 1 | {}<br />[] | Pattern Match<br />Array Subscripting | Left-to-right |
| 2 | !<br />*<br />@<br />? | GetProcAddress<br />Indirection (dereference)<br />Relocate<br />Null Check | Right-to-left |
| 3 | * | Multiplication | Left-to-right |
| 4 | +<br />- | Addition<br />Subtraction | Left-to-right |

## Sinker Compiler

The Sinker Compiler can be used to amalgamate multiple Sinker DSL files into one file. It can also be used to generate a `.def` header file that can be included in C++ source code with useful macros and boilerplate code for the Sinker Runtime Library.

The compiler accepts a list of positional input source file paths that will be evaluated in the order the arguments are specified. The `-o <amalgamated_file_path>` option can be used to specify where the output file should go. If this option is missing, then no `.skr` file will be output. Finally, the `-d <def_file_path>` can be used to specify where the `.def` file should go. If this option is missing, then no `.def` file will be output.

### `.def`

For the following `.skr` file

```plaintext
module crackme;
variant crackme, v1_0_0, "deadbeefdeadbeefdeadbeefdeadbeef"
symbol check_flag, "bool(*)(char const * flag)";
tag crackme::check_flag, hook;
address crackme::check_flag, v1_0_0, @0xc0dec0de;
```

The `.def` file will contain the following:

```cpp
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
```

and it can be used like the following simple example:

```cpp
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
```

The macros can be redefined and the `.def` can be included as many times as necessary.

## Sinker Runtime Library

Look at the header libraries for now. I'll start generating documentation using Doxygen at some point.

## Getting Started

### Prerequisites

* Git
* CMake
* Bison or [WinFlexBison](https://github.com/lexxmark/winflexbison)

### Checkout

```sh
git clone https://github.com/widberg/sinker.git --recurse-submodules --shallow-submodules
```

### Building On Windows

Use the `x86 Native Tools Command Prompt for VS 2022` environment while generating and building the
project.

#### Ninja

```sh
cmake -B build -G Ninja
cmake --build build
```
