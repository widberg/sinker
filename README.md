# Sinker

[![Build Status](https://github.com/widberg/sinker/actions/workflows/tests.yml/badge.svg?branch=master)](https://github.com/widberg/sinker/actions/workflows/tests.yml)
[![Documentation Status](https://readthedocs.org/projects/sinker/badge/?version=latest)](https://sinker.readthedocs.io/en/latest/?badge=latest)

Instrument Windows binaries hook, line, and sinker at runtime with this batteries included hook specification and installation suite. [Sinker DSL](https://sinker.readthedocs.io/en/latest/sinkerdsl.html) is a simple domain-specific language for specifying addresses in a loaded module programmatically. The [Sinker Compiler](https://sinker.readthedocs.io/en/latest/sinkercompiler.html) makes it easy to amalgamate many Sinker DSL files and produce `.def` headers for easy use of the Sinker Runtime Library from C++. The [Sinker Runtime Library](https://sinker.readthedocs.io/en/latest/sinkerruntimelibrary.html) installs the specified hooks into a module at runtime.

## Documentation

The documentation is hosted on [Read the Docs](https://sinker.readthedocs.io/en/latest/).

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

Use the `x86/64 Native Tools Command Prompt for VS 2022` environment while generating and building the
project.

#### Ninja

```sh
cmake -B build -G Ninja
cmake --build build
```
