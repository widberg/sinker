# Sinker

[![Build Status](https://github.com/widberg/sinker/actions/workflows/tests.yml/badge.svg?branch=master)](https://github.com/widberg/sinker/actions/workflows/tests.yml)
[![Documentation Status](https://readthedocs.org/projects/sinker/badge/?version=latest)](https://sinker.readthedocs.io/en/latest/?badge=latest)

```cpp
//$ symbol game::CoreMainLoop, "void (__stdcall *)()";
//$ tag game::CoreMainLoop, hook;
//$ address game::CoreMainLoop, [retail], @0x00688bf0;
void __stdcall wrap_game_CoreMainLoop() {
    BROADCAST(Tick);

    // Do stuff before the real game::CoreMainLoop() is called.

    real_game_CoreMainLoop();

    // Do stuff after the real game::CoreMainLoop() is called.
}
```

Instrument Windows binaries hook, line, and sinker at runtime with this batteries included hook specification and installation suite. [Sinker Script](https://sinker.readthedocs.io/en/latest/sinkerscript.html) is a simple domain-specific language for specifying addresses in a loaded module programmatically. The [Sinker Compiler](https://sinker.readthedocs.io/en/latest/sinkercompiler.html) makes it easy to amalgamate many Sinker Script files and produce `.def` headers for easy use of the Sinker Runtime Library from C++. The [Sinker Runtime Library](https://sinker.readthedocs.io/en/latest/sinkerruntimelibrary.html) installs the specified hooks into a module at runtime.

## Documentation

The documentation is hosted on [Read the Docs](https://sinker.readthedocs.io/en/latest/).

## Getting Started

Instructions on how to include Sinker in your CMake project can be found in the [CMake Integration](https://sinker.readthedocs.io/en/latest/cmakeintegration.html) section of the documentation. I recommend reading the rest of the documentation first to get a feel for how Sinker works.

## Contributing

Instructions on how to build and test the project.

### Prerequisites

* Git
* CMake
* Bison or [WinFlexBison](https://github.com/lexxmark/winflexbison) (Optional<sup>†</sup>)
†<sub>Only needed if editing the Script grammar file.</sub>

### Checkout

```sh
git clone https://github.com/widberg/sinker.git --recurse-submodules --shallow-submodules
```

#### Build and Test

```sh
cmake -B build -DSINKER_BUILD_TESTS=ON
cmake --build build --target check-sinker
```
