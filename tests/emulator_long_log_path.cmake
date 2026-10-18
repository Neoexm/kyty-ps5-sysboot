if(NOT DEFINED EMULATOR OR NOT DEFINED WORK_DIR)
	message(FATAL_ERROR "emulator_long_log_path.cmake requires EMULATOR and WORK_DIR")
endif()

# longPathAware in the manifest is ignored unless the machine opts in.
execute_process(COMMAND reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\FileSystem" /v LongPathsEnabled
	OUTPUT_VARIABLE reg_output RESULT_VARIABLE reg_result ERROR_QUIET)
if(NOT reg_result EQUAL 0 OR NOT reg_output MATCHES "LongPathsEnabled[ \t]+REG_DWORD[ \t]+0x1")
	message("LongPathsEnabled is not set; skipping")
	cmake_language(EXIT 77)
endif()

file(REMOVE_RECURSE "${WORK_DIR}")
file(MAKE_DIRECTORY "${WORK_DIR}/app0")
string(REPEAT "z" 64 junk)
file(WRITE "${WORK_DIR}/app0/eboot.bin" "${junk}")

file(TO_NATIVE_PATH "${WORK_DIR}/" log_dir)
string(LENGTH "${log_dir}" dir_length)
math(EXPR name_length "300 - ${dir_length} - 4")
string(REPEAT "x" ${name_length} name)
set(log "${log_dir}${name}.log")

execute_process(COMMAND "${EMULATOR}" --game "${WORK_DIR}/app0" --printf-direction File --printf-output-file "${log}"
	RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE output TIMEOUT 120)
if(NOT EXISTS "${WORK_DIR}/${name}.log")
	message(FATAL_ERROR "no log at a 300 character path (exit ${result}):\n${output}")
endif()
if(output MATCHES "spdlog fatal error")
	message(FATAL_ERROR "spdlog failed to open a 300 character log path:\n${output}")
endif()
# 321 is the invalid-ELF exit; anything else means startup did not get as far as the loader.
if(NOT result EQUAL 321)
	message(FATAL_ERROR "unexpected exit ${result}:\n${output}")
endif()
file(REMOVE_RECURSE "${WORK_DIR}")
