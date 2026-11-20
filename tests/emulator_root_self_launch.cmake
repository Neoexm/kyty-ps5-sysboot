if(NOT DEFINED EMULATOR OR NOT DEFINED FIXTURE_TOOL OR NOT DEFINED WORK_DIR)
	message(FATAL_ERROR "emulator_root_self_launch.cmake requires EMULATOR, FIXTURE_TOOL and WORK_DIR")
endif()

file(REMOVE_RECURSE "${WORK_DIR}")
file(MAKE_DIRECTORY "${WORK_DIR}/dump" "${WORK_DIR}/work" "${WORK_DIR}/eboot" "${WORK_DIR}/other")
execute_process(COMMAND "${FIXTURE_TOOL}" --write-root-self-fixture "${WORK_DIR}/dump" RESULT_VARIABLE result)
if(NOT result EQUAL 0)
	message(FATAL_ERROR "fixture writer failed: ${result}")
endif()
file(SHA256 "${WORK_DIR}/dump/root.self" self_sha256)
file(SHA256 "${WORK_DIR}/dump/root.authinfo" capture_sha256)
file(COPY_FILE "${WORK_DIR}/dump/root.elf" "${WORK_DIR}/eboot/eboot.bin")
file(RENAME "${WORK_DIR}/dump/other.elf" "${WORK_DIR}/other/root.elf")

# No args beyond --game/--sysroot/log and cwd outside the dump, same as a launcher boot.
function(launch name cwd expect_exit)
	set(log "${WORK_DIR}/${name}.log")
	execute_process(COMMAND "${CMAKE_COMMAND}" -E env
		"KYTY_DIAGNOSTIC_ORIGINAL_SELF=${WORK_DIR}/dump/root.self" KYTY_DIAGNOSTIC_ROOT_SELF_VALIDATE_ONLY=1
		"${EMULATOR}" ${ARGN} --printf-direction File --printf-output-file "${log}"
		WORKING_DIRECTORY "${cwd}" RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE output TIMEOUT 120)
	if(NOT EXISTS "${log}")
		message(FATAL_ERROR "${name}: no log (exit ${result}):\n${output}")
	endif()
	file(READ "${log}" text)
	if(NOT result EQUAL expect_exit)
		message(FATAL_ERROR "${name}: exit ${result}, expected ${expect_exit}:\n${text}")
	endif()
	if(text MATCHES "MODULE_LOAD_ONLY|STATIC_EXEC_LOAD_ONLY|Unintercepted native static")
		message(FATAL_ERROR "${name}: got past the validate-only exit:\n${text}")
	endif()
	set(text "${text}" PARENT_SCOPE)
endfunction()

function(expect_match name elf leaf)
	if(NOT text MATCHES "ROOT_ORIGINAL_SELF_VERIFIED self_sha256=${self_sha256} ")
		message(FATAL_ERROR "${name}: root SELF not verified as ${self_sha256}:\n${text}")
	endif()
	if(NOT text MATCHES "ROOT_ORIGINAL_SELF_LOAD_MATCH elf=${elf} loaded=[^\r\n]*${leaf}\r?\n")
		message(FATAL_ERROR "${name}: loader did not resolve ${elf} to the validated file:\n${text}")
	endif()
	message("${name}: ${CMAKE_MATCH_0}")
	if(NOT text MATCHES "ROOT_SELF_VALIDATE_ONLY\r?\n")
		message(FATAL_ERROR "${name}: no validate-only exit:\n${text}")
	endif()
endfunction()

launch(launcher "${WORK_DIR}/work" 0 --game "${WORK_DIR}/dump/root.elf" --sysroot "${WORK_DIR}/dump")
expect_match(launcher "/app0/root.elf" "root.elf")

function(launch_capture name hash expect_exit)
	set(log "${WORK_DIR}/${name}.log")
	execute_process(COMMAND "${CMAKE_COMMAND}" -E env
		"KYTY_DIAGNOSTIC_ORIGINAL_SELF=${WORK_DIR}/dump/root.self"
		"KYTY_PS5_CAPTURED_AUTHINFO_${self_sha256}=${WORK_DIR}/dump/root.authinfo"
		"KYTY_PS5_CAPTURED_AUTHINFO_SHA256_${self_sha256}=${hash}"
		KYTY_DIAGNOSTIC_ROOT_SELF_VALIDATE_ONLY=1
		"${EMULATOR}" --game "${WORK_DIR}/dump/root.elf" --sysroot "${WORK_DIR}/dump"
		--printf-direction File --printf-output-file "${log}"
		WORKING_DIRECTORY "${WORK_DIR}/work" RESULT_VARIABLE result
		OUTPUT_VARIABLE output ERROR_VARIABLE output TIMEOUT 120)
	if(NOT EXISTS "${log}")
		message(FATAL_ERROR "${name}: no log (exit ${result}):\n${output}")
	endif()
	file(READ "${log}" text)
	if(NOT result EQUAL expect_exit)
		message(FATAL_ERROR "${name}: exit ${result}, expected ${expect_exit}:\n${text}")
	endif()
	set(text "${text}" PARENT_SCOPE)
endfunction()

launch_capture(captured "${capture_sha256}" 0)
if(NOT text MATCHES "AUTHINFO_CAPTURE_INPUT provenance=environment root=1 envelope_sha256=${capture_sha256} [^\r\n]*status=verified")
	message(FATAL_ERROR "captured: full root record was not verified:\n${text}")
endif()
if(NOT text MATCHES "ROOT_SELF_VALIDATE_ONLY\r?\n")
	message(FATAL_ERROR "captured: no validate-only exit:\n${text}")
endif()

string(REPEAT "0" 64 wrong_capture_sha256)
launch_capture(wrong_capture_hash "${wrong_capture_sha256}" 321)
if(NOT text MATCHES "AUTHINFO_CAPTURE_INPUT provenance=environment root=1 status=rejected reason=")
	message(FATAL_ERROR "wrong_capture_hash: no capture rejection:\n${text}")
endif()
if(text MATCHES "ROOT_SELF_VALIDATE_ONLY")
	message(FATAL_ERROR "wrong_capture_hash: reached validate-only exit:\n${text}")
endif()

launch(relative "${WORK_DIR}" 0 --game "dump/root.elf")
expect_match(relative "/app0/root.elf" "root.elf")

launch(directory "${WORK_DIR}/work" 0 --game "${WORK_DIR}/eboot")
expect_match(directory "/app0/eboot.bin" "eboot.bin")

# Same name, different program header: the SELF must not vouch for it.
launch(wrong_elf "${WORK_DIR}/work" 321 --game "${WORK_DIR}/other/root.elf")
if(NOT text MATCHES "ROOT_ORIGINAL_SELF_REJECTED reason=ELF program header mismatch ")
	message(FATAL_ERROR "wrong_elf: not rejected:\n${text}")
endif()
string(REGEX MATCH "ROOT_ORIGINAL_SELF_REJECTED reason=[^\r\n]*" rejected "${text}")
if(text MATCHES "ROOT_ORIGINAL_SELF_VERIFIED|ROOT_SELF_VALIDATE_ONLY")
	message(FATAL_ERROR "wrong_elf: accepted:\n${text}")
endif()
message("wrong_elf: ${rejected}")

file(REMOVE_RECURSE "${WORK_DIR}")
