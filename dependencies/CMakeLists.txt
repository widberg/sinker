# Catch2
if(SINKER_BUILD_TESTS AND NOT TARGET Catch2::Catch2WithMain)
    add_subdirectory(Catch2)
endif()

# CLI11
if(NOT TARGET CLI11::CLI11)
    add_subdirectory(CLI11)
endif()

# Detours
if(NOT TARGET detours)
    add_subdirectory(detours)
endif()

# hashlibpp
if(NOT TARGET hl++)
    add_subdirectory(hashlibpp)
    target_include_directories(hl++ PUBLIC $<TARGET_PROPERTY:hl++,SOURCE_DIR>/src)
endif()

# re2c
if(SINKER_BUILD_GRAMMAR AND NOT TARGET re2c)
    add_subdirectory(re2c)
endif()

# bison
if(SINKER_BUILD_GRAMMAR)
    find_package(BISON 3.4.1 REQUIRED)
endif()
