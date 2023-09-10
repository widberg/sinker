cmake_minimum_required(VERSION 3.14)

if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
  message(FATAL_ERROR "Prevented in-tree built. Please create a build directory outside of the sinker source code and call cmake from there")
endif()

if (POLICY CMP0048)
  cmake_policy(SET CMP0048 NEW)
endif()

if (POLICY CMP0074)
  cmake_policy(SET CMP0074 NEW)
endif()

if (POLICY CMP0091)
	cmake_policy(SET CMP0091 NEW)
endif()

project(sinker VERSION 0.0.1 LANGUAGES CXX)

option(SINKER_BUILD_TESTS "Build tests" OFF)

set(CMAKE_CXX_STANDARD 17 CACHE INTERNAL "")
set(CMAKE_CXX_STANDARD_REQUIRED ON CACHE INTERNAL "")

add_subdirectory(dependencies)
add_subdirectory(sinker)
add_subdirectory(sinkerc)

if(SINKER_BUILD_TESTS)
  add_executable(sinker-tests
    tests/test.cpp
  )
  target_link_libraries(sinker-tests PRIVATE Catch2::Catch2WithMain sinker)

  add_custom_target(check-sinker
      COMMAND "${CMAKE_CTEST_COMMAND}" --output-on-failure
      USES_TERMINAL
      DEPENDS sinker-tests
      COMMENT "Build and run all the tests.")

  list(APPEND CMAKE_MODULE_PATH ${Catch2_SOURCE_DIR}/extras)
  include(CTest)
  include(Catch)
  catch_discover_tests(sinker-tests)
endif()
