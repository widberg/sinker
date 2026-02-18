# Catch2
if(SINKER_BUILD_TESTS AND NOT TARGET Catch2::Catch2WithMain)
    add_subdirectory(Catch2 EXCLUDE_FROM_ALL)
endif()

# CLI11
if(NOT TARGET CLI11::CLI11)
    add_subdirectory(CLI11 EXCLUDE_FROM_ALL)
endif()

# Detours
if(NOT TARGET detours)
    add_subdirectory(detours EXCLUDE_FROM_ALL)
endif()

# sha256
add_subdirectory(sha256 EXCLUDE_FROM_ALL)

if(SINKER_BUILD_GRAMMAR)
    if(NOT RE2C_EXECUTABLE)
        find_program(RE2C_EXECUTABLE re2c)
    endif()
    if(NOT BISON_FOUND)
        find_package(BISON 3.4.1 REQUIRED)
    endif()
endif()
