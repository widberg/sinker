add_executable(sinkerc
		main.cpp
)
target_link_libraries(sinkerc sinker CLI11::CLI11)

macro(add_sinker_target SINKER_TARGET)
	set(options )
	set(oneValueArgs OUTPUT DEFINITIONS)
	set(multiValueArgs INPUT)
	cmake_parse_arguments(SINKER "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN} )
	add_custom_command(
		OUTPUT ${SINKER_OUTPUT}
		COMMAND_EXPAND_LISTS
		VERBATIM
		COMMAND $<TARGET_FILE:sinkerc> ${SINKER_INPUT} $<$<BOOL:${SINKER_OUTPUT}>:-o> ${SINKER_OUTPUT} $<$<BOOL:${SINKER_DEFINITIONS}>:-d> ${SINKER_DEFINITIONS}
		DEPENDS sinkerc ${SINKER_INPUT}
		WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
	)
	add_custom_target(${SINKER_TARGET} DEPENDS ${SINKER_OUTPUT})
endmacro()
