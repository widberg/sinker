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
if(NOT TARGET re2c)
    add_subdirectory(re2c)
endif()

# bison
find_package(BISON 3.4.1 REQUIRED)
