CMake Integration
=================

Adding Sinker to Your CMake Project
-----------------------------------

The Sinker source code can be included in your project via a Git submodule or via CMake's ``FetchContent`` module.

Git Submodule
^^^^^^^^^^^^^

First, run the command

.. code-block:: bash

    git submodule add https://github.com/widberg/sinker.git

then add the following to your ``CMakeLists.txt``

.. code-block:: cmake

    add_subdirectory(sinker)

FetchContent
^^^^^^^^^^^^

If you don't want to use a Git submodule then add the following to your ``CMakeLists.txt``

.. code-block:: cmake

    Include(FetchContent)

    FetchContent_Declare(
        Sinker
        GIT_REPOSITORY https://github.com/widberg/sinker.git
        GIT_TAG        some_commit_hash
    )

    FetchContent_MakeAvailable(Sinker)

Sinker Compiler Target
----------------------

You can define a target that runs the Sinker compiler on a list of input files and outputs a ``.skr`` file and a ``.def`` file.

.. code-block:: cmake

    add_sinker_target(my_sinker_target
        INPUT
            my_sinker_modules.skr
            main.cpp
            instrument.cpp
            my_other_source.cpp
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/my_sinker_target.skr
        DEFINITIONS ${CMAKE_CURRENT_BINARY_DIR}/include/my_sinker_target.def
    )

The list of all sources for a target can be retrieved with ``get_target_property``

.. code-block:: cmake

    get_target_property(MY_TARGET_SOURCES my_target SOURCES)
    add_sinker_target(my_sinker_target
        INPUT
            ${MY_TARGET_SOURCES}
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/my_sinker_target.skr
        DEFINITIONS ${CMAKE_CURRENT_BINARY_DIR}/include/my_sinker_target.def
    )

To access the ``.def`` file with includes in my_target, you can use the following:

.. code-block:: cmake

    target_include_directories(my_target
        PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/include
    )

Sinker Runtime Library
----------------------

The Sinker runtime library can be linked with your target by adding the following to your ``CMakeLists.txt``

.. code-block:: cmake

    target_link_libraries(my_target
        PRIVATE sinker
    )
