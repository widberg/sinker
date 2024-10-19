add_library(sha256 STATIC
    sha256.cpp
    include/sha256.hpp
)
target_include_directories(sha256 PUBLIC include)

add_executable(sha256sum
    sha256sum.cpp
)
target_link_libraries(sha256sum PRIVATE sha256 CLI11::CLI11)
