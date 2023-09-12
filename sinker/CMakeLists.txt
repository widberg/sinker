add_library(sinker STATIC
	src/sinker.cpp
	include/sinker/sinker.hpp
	include/sinker/sinker.tpp
	src/parser.yy
	src/parser.cpp
)
target_include_directories(sinker PUBLIC include)
target_link_libraries(sinker hl++ detours)
target_link_options(sinker INTERFACE /export:DetourFinishHelperProcess,@1,NONAME)

if(SINKER_BUILD_GRAMMAR)
	add_custom_command(
		OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/src/parser.cpp
		BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/parser.cpp.re
		COMMAND ${BISON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/src/parser.yy -o ${CMAKE_CURRENT_BINARY_DIR}/parser.cpp.re -Wcounterexamples
		COMMAND $<TARGET_FILE:re2c> ${CMAKE_CURRENT_BINARY_DIR}/parser.cpp.re -o ${CMAKE_CURRENT_SOURCE_DIR}/src/parser.cpp --no-debug-info
		DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/parser.yy
	)
endif()
