set(input "${CMAKE_CURRENT_BINARY_DIR}/cli-input.txt")
file(WRITE "${input}" "bad\n1\n2\n3\n0\n")
execute_process(COMMAND "${APP}" INPUT_FILE "${input}"
    OUTPUT_VARIABLE output ERROR_VARIABLE errors RESULT_VARIABLE result TIMEOUT 5)
if(NOT result STREQUAL "0" OR NOT output MATCHES "Choose an option"
   OR NOT errors MATCHES "Password generation requires an interactive Windows console"
   OR NOT errors MATCHES "Managing credentials requires an interactive Windows console"
   OR output MATCHES "Character sets|Entry label|Base32 setup key")
    message(FATAL_ERROR "Unexpected behavior with redirected console streams.\n${output}\n${errors}")
endif()

file(WRITE "${input}" "")
execute_process(COMMAND "${APP}" INPUT_FILE "${input}"
    OUTPUT_QUIET ERROR_VARIABLE errors RESULT_VARIABLE result TIMEOUT 5)
file(REMOVE "${input}")
if(NOT result STREQUAL "0" OR errors)
    message(FATAL_ERROR "The CLI did not exit cleanly on end-of-input.\n${errors}")
endif()
