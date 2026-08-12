cmake_minimum_required(VERSION 4.4.2)

project(
	ExeCell
	VERSION 0.2.0
	DESCRIPTION "Linux process inspection and sandboxing toolkit"
	LANGUAGES CXX
)

find_path(LIBARCHIVE_INCLUDE_DIR archive.h REQUIRED)
find_library(LIBARCHIVE_LIBRARY archive REQUIRED)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "ExeCell requires Linux")
endif()

include(CTest)

# Storage is optional so core sandbox builds remain usable on hosts without SQLite.
find_package(SQLite3 QUIET)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
option(EXECELL_ENABLE_ADDRESS_SANITIZER "Enable ASan and UBSan in Debug builds" ON)
option(EXECELL_ENABLE_FUZZING "Build Clang libFuzzer targets" OFF)

add_executable(execell
	src/main.cpp
	
	src/process/process.cpp
	
	src/trace/tracer.cpp
	src/trace/stop.cpp
	src/trace/architecture.cpp
	src/trace/memory.cpp
	src/trace/syscall.cpp
	src/trace/fd_table.cpp
	
	src/report/terminal_reporter.cpp
	src/report/summary_reporter.cpp
	src/report/json_reporter.cpp
	src/policy/policy.cpp
	src/policy/policy_reporter.cpp
	src/sandbox/sandbox.cpp
	src/sandbox/backend.cpp

	src/trace/syscall_decoder.cpp

	src/package/package.cpp
	src/package/archive.cpp
	src/package/aur.cpp
	src/package/build.cpp
	src/package/rootfs.cpp
	src/package/observation.cpp
	src/package/network.cpp
	src/risk/risk.cpp
	src/analyze/analyze.cpp
)

add_executable(execell_manual_fixture examples/manual_fixture.cpp)
target_compile_features(execell_manual_fixture PRIVATE cxx_std_23)
target_compile_options(execell_manual_fixture PRIVATE
	-Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow
	-Wformat=2 -Wundef -Werror
)

add_executable(execell_analyze_output_fixture tests/analyze_output_fixture.cpp)
add_executable(execell_analyze_timeout_fixture tests/analyze_timeout_fixture.cpp)
foreach(analyze_fixture IN ITEMS execell_analyze_output_fixture execell_analyze_timeout_fixture)
    target_compile_features(${analyze_fixture} PRIVATE cxx_std_23)
    target_compile_options(${analyze_fixture} PRIVATE -Wall -Wextra -Wpedantic -Werror)
endforeach()

target_compile_features(execell PRIVATE cxx_std_23)

if(SQLite3_FOUND)
    add_library(execell_storage STATIC src/package/storage.cpp)
    target_include_directories(execell_storage PUBLIC ${PROJECT_SOURCE_DIR}/include)
    target_compile_features(execell_storage PUBLIC cxx_std_23)
    target_compile_options(execell_storage PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow
        -Wformat=2 -Wundef -Werror
    )
    if(TARGET SQLite3::SQLite3)
        target_link_libraries(execell_storage PUBLIC SQLite3::SQLite3)
    elseif(TARGET SQLite::SQLite3)
        target_link_libraries(execell_storage PUBLIC SQLite::SQLite3)
    else()
        target_include_directories(execell_storage PRIVATE ${SQLite3_INCLUDE_DIRS})
        target_link_libraries(execell_storage PUBLIC ${SQLite3_LIBRARIES})
    endif()
else()
    message(WARNING "SQLite3 not found; SQLite baseline storage targets disabled")
endif()

target_include_directories(execell
	PRIVATE
		${PROJECT_SOURCE_DIR}/include
		${LIBARCHIVE_INCLUDE_DIR}
)

target_link_libraries(execell PRIVATE ${LIBARCHIVE_LIBRARY})
if(SQLite3_FOUND)
    target_link_libraries(execell PRIVATE execell_storage)
    target_compile_definitions(execell PRIVATE EXECELL_HAVE_SQLITE=1)
endif()

target_compile_options(execell
	PRIVATE
		-Wall
		-Wextra
		-Wpedantic
		-Wconversion
		-Wsign-conversion
		-Wshadow
		-Wformat=2
		-Wundef
		-Werror
)


if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND EXECELL_ENABLE_ADDRESS_SANITIZER)
		    target_compile_options(execell PRIVATE
			   -fsanitize=address,undefined
			   -fno-omit-frame-pointer
                    )

		    target_link_options(execell PRIVATE
		     	   -fsanitize=address,undefined
                    )

endif()

if(BUILD_TESTING)
    if(SQLite3_FOUND)
        add_executable(execell_storage_test tests/storage_test.cpp)
        target_link_libraries(execell_storage_test PRIVATE execell_storage)
        target_compile_features(execell_storage_test PRIVATE cxx_std_23)
        target_compile_options(execell_storage_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
        add_test(NAME package_storage COMMAND execell_storage_test)
    endif()

    add_executable(execell_fd_table_test
        tests/fd_table_test.cpp
        src/trace/fd_table.cpp
    )

    target_include_directories(execell_fd_table_test
        PRIVATE
            ${PROJECT_SOURCE_DIR}/include
    )

    target_compile_features(execell_fd_table_test PRIVATE cxx_std_23)
    target_compile_options(execell_fd_table_test PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wsign-conversion
        -Wshadow
        -Wformat=2
        -Wundef
    )

    add_test(NAME fd_table COMMAND execell_fd_table_test)

    add_executable(execell_stop_test
        tests/stop_test.cpp
        src/trace/stop.cpp
    )
    target_include_directories(execell_stop_test PRIVATE ${PROJECT_SOURCE_DIR}/include)
    target_compile_features(execell_stop_test PRIVATE cxx_std_23)
    add_test(NAME stop_classification COMMAND execell_stop_test)

    add_executable(execell_memory_test
        tests/memory_test.cpp
        src/trace/memory.cpp
    )
    target_include_directories(execell_memory_test PRIVATE ${PROJECT_SOURCE_DIR}/include)
    target_compile_features(execell_memory_test PRIVATE cxx_std_23)
    add_test(NAME memory_read COMMAND execell_memory_test)

    add_executable(execell_json_test
        tests/json_reporter_test.cpp
        src/report/json_reporter.cpp
    )
    target_include_directories(execell_json_test PRIVATE ${PROJECT_SOURCE_DIR}/include)
    target_compile_features(execell_json_test PRIVATE cxx_std_23)
    add_test(NAME json_reporter COMMAND execell_json_test)

    add_executable(execell_risk_network_test
        tests/risk_network_test.cpp
        src/risk/risk.cpp
        src/package/network.cpp
    )
    target_include_directories(execell_risk_network_test PRIVATE ${PROJECT_SOURCE_DIR}/include)
    target_compile_features(execell_risk_network_test PRIVATE cxx_std_23)
    target_compile_options(execell_risk_network_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME risk_network COMMAND execell_risk_network_test)

    add_executable(execell_package_test
        tests/package_test.cpp
        src/package/package.cpp
        src/package/archive.cpp
        src/package/aur.cpp
        src/package/build.cpp
        src/package/rootfs.cpp
        src/package/observation.cpp
        src/sandbox/sandbox.cpp
        src/risk/risk.cpp
        src/package/network.cpp
    )
    target_include_directories(execell_package_test PRIVATE ${PROJECT_SOURCE_DIR}/include)
    target_include_directories(execell_package_test PRIVATE ${LIBARCHIVE_INCLUDE_DIR})
    target_link_libraries(execell_package_test PRIVATE ${LIBARCHIVE_LIBRARY})
    if(SQLite3_FOUND)
        target_link_libraries(execell_package_test PRIVATE execell_storage)
        target_compile_definitions(execell_package_test PRIVATE EXECELL_HAVE_SQLITE=1)
    endif()
    target_compile_features(execell_package_test PRIVATE cxx_std_23)
    target_compile_options(execell_package_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME package_subsystem COMMAND execell_package_test)

    add_executable(execell_aur_test
        tests/aur_test.cpp
        src/package/aur.cpp
        src/package/build.cpp
        src/package/rootfs.cpp
        src/sandbox/sandbox.cpp
    )
    target_include_directories(execell_aur_test PRIVATE ${PROJECT_SOURCE_DIR}/include)
    target_compile_features(execell_aur_test PRIVATE cxx_std_23)
    target_compile_options(execell_aur_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME aur_parser COMMAND execell_aur_test)

    add_executable(execell_archive_test
        tests/archive_test.cpp
        src/package/archive.cpp
    )
    target_include_directories(execell_archive_test PRIVATE
        ${PROJECT_SOURCE_DIR}/include ${LIBARCHIVE_INCLUDE_DIR})
    target_compile_features(execell_archive_test PRIVATE cxx_std_23)
    target_compile_options(execell_archive_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
    target_link_libraries(execell_archive_test PRIVATE ${LIBARCHIVE_LIBRARY})
    add_test(NAME archive_adapter COMMAND execell_archive_test)

    if(EXECELL_ENABLE_FUZZING AND CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        add_executable(execell_archive_fuzz
            tests/archive_fuzz.cpp
            src/package/archive.cpp
        )
        target_include_directories(execell_archive_fuzz PRIVATE
            ${PROJECT_SOURCE_DIR}/include ${LIBARCHIVE_INCLUDE_DIR})
        target_compile_features(execell_archive_fuzz PRIVATE cxx_std_23)
        target_compile_options(execell_archive_fuzz PRIVATE
            -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
        target_link_options(execell_archive_fuzz PRIVATE
            -fsanitize=fuzzer,address,undefined)
        target_link_libraries(execell_archive_fuzz PRIVATE ${LIBARCHIVE_LIBRARY})
    endif()

    add_executable(execell_arch_acceptance
        tests/arch_acceptance.cpp
        src/package/rootfs.cpp
    )
    target_include_directories(execell_arch_acceptance PRIVATE ${PROJECT_SOURCE_DIR}/include)
    target_compile_features(execell_arch_acceptance PRIVATE cxx_std_23)
    target_compile_options(execell_arch_acceptance PRIVATE -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME arch_rootfs_acceptance COMMAND execell_arch_acceptance)
    set_tests_properties(arch_rootfs_acceptance PROPERTIES SKIP_RETURN_CODE 77)

    add_executable(execell_trace_fixture tests/trace_fixture.cpp)
    target_compile_features(execell_trace_fixture PRIVATE cxx_std_23)
    add_test(
        NAME trace_fixture
        COMMAND execell trace $<TARGET_FILE:execell_trace_fixture>
    )
    add_test(
        NAME inspect_fixture
        COMMAND execell inspect $<TARGET_FILE:execell_trace_fixture>
    )
    add_test(
        NAME analyze_manual_fixture
        COMMAND execell analyze $<TARGET_FILE:execell_manual_fixture> file
    )
    add_test(
        NAME analyze_policy_reject
        COMMAND execell analyze --deny-path /tmp $<TARGET_FILE:execell_manual_fixture> file
    )
    set_tests_properties(analyze_policy_reject PROPERTIES WILL_FAIL TRUE)
    add_test(
        NAME analyze_timeout
        COMMAND execell analyze --sandbox --timeout 1 $<TARGET_FILE:execell_analyze_timeout_fixture>
    )
    set_tests_properties(analyze_timeout PROPERTIES WILL_FAIL TRUE TIMEOUT 5)
    add_test(
        NAME analyze_output_limit
        COMMAND execell analyze --sandbox --output-limit 128 $<TARGET_FILE:execell_analyze_output_fixture>
    )
    set_tests_properties(analyze_output_limit PROPERTIES WILL_FAIL TRUE TIMEOUT 5)
    add_test(
        NAME analyze_json_schema
        COMMAND sh -c
                "$<TARGET_FILE:execell> analyze --format json $<TARGET_FILE:execell_manual_fixture> file > /tmp/execell-analyze-schema.json && python3 -c 'import json; x=json.load(open(\"/tmp/execell-analyze-schema.json\")); assert x[\"schema_version\"] == 2; assert \"findings\" in x; assert \"events\" in x; y=json.load(open(x[\"session\"] + \"/summary.json\")); assert y[\"verdict\"] == x[\"verdict\"]'")
    add_test(
        NAME package_doctor_root_default
        COMMAND execell package doctor --format json
    )
    add_test(NAME sandbox_trace_events COMMAND execell sandbox --trace-events /bin/true)

    add_executable(execell_network_fixture tests/network_fixture.cpp)
    target_compile_features(execell_network_fixture PRIVATE cxx_std_23)
    add_test(
        NAME network_fixture
        COMMAND execell trace $<TARGET_FILE:execell_network_fixture>
    )
    add_test(
        NAME network_deny
        COMMAND execell inspect --deny-endpoint 127.0.0.1 $<TARGET_FILE:execell_network_fixture>
    )
    set_tests_properties(network_deny PROPERTIES WILL_FAIL TRUE)
    add_test(
        NAME process_limit
        COMMAND execell inspect --max-processes 1 $<TARGET_FILE:execell_process_limit_fixture>
    )
    set_tests_properties(process_limit PROPERTIES WILL_FAIL TRUE)
    add_executable(execell_process_limit_fixture tests/process_limit_fixture.cpp)
    target_compile_features(execell_process_limit_fixture PRIVATE cxx_std_23)

    add_executable(execell_signal_fixture tests/signal_fixture.cpp)
    target_compile_features(execell_signal_fixture PRIVATE cxx_std_23)
    add_test(
        NAME signal_fixture
        COMMAND execell trace $<TARGET_FILE:execell_signal_fixture>
    )
    set_tests_properties(signal_fixture PROPERTIES WILL_FAIL TRUE)

    add_executable(execell_exec_fixture tests/exec_fixture.cpp)
    target_compile_features(execell_exec_fixture PRIVATE cxx_std_23)
    add_test(
        NAME exec_fixture
        COMMAND execell trace $<TARGET_FILE:execell_exec_fixture>
    )

    add_executable(execell_crash_fixture tests/crash_fixture.cpp)
    target_compile_features(execell_crash_fixture PRIVATE cxx_std_23)
    add_test(
        NAME crash_fixture
        COMMAND execell trace $<TARGET_FILE:execell_crash_fixture>
    )
    set_tests_properties(crash_fixture PROPERTIES WILL_FAIL TRUE)

    add_executable(execell_exit_status_fixture tests/exit_status_fixture.cpp)
    target_compile_features(execell_exit_status_fixture PRIVATE cxx_std_23)
    add_test(
        NAME exit_status_fixture
        COMMAND execell trace $<TARGET_FILE:execell_exit_status_fixture>
    )
    set_tests_properties(exit_status_fixture PROPERTIES WILL_FAIL TRUE)

    add_executable(execell_policy_sandbox_test
        tests/policy_sandbox_test.cpp
        src/policy/policy.cpp
        src/policy/policy_reporter.cpp
        src/report/summary_reporter.cpp
        src/sandbox/sandbox.cpp
    )
    target_include_directories(execell_policy_sandbox_test PRIVATE ${PROJECT_SOURCE_DIR}/include)
    target_compile_features(execell_policy_sandbox_test PRIVATE cxx_std_23)
    add_test(NAME policy_sandbox COMMAND execell_policy_sandbox_test)

    add_executable(execell_sandbox_isolation_test
        tests/sandbox_isolation_test.cpp
        src/sandbox/sandbox.cpp
    )
    target_include_directories(execell_sandbox_isolation_test PRIVATE ${PROJECT_SOURCE_DIR}/include)
    target_compile_features(execell_sandbox_isolation_test PRIVATE cxx_std_23)
    target_compile_options(execell_sandbox_isolation_test PRIVATE -Werror)
    add_test(NAME sandbox_isolation COMMAND execell_sandbox_isolation_test)
    set_tests_properties(sandbox_isolation PROPERTIES SKIP_RETURN_CODE 77)

    add_executable(execell_sandbox_cpu_test
        tests/sandbox_cpu_test.cpp
        src/sandbox/sandbox.cpp
    )
    target_include_directories(execell_sandbox_cpu_test PRIVATE ${PROJECT_SOURCE_DIR}/include)
    target_compile_features(execell_sandbox_cpu_test PRIVATE cxx_std_23)
    target_compile_options(execell_sandbox_cpu_test PRIVATE -Werror)
    add_test(NAME sandbox_cpu_limit COMMAND execell_sandbox_cpu_test)
    set_tests_properties(sandbox_cpu_limit PROPERTIES TIMEOUT 5)

    add_executable(execell_memory_bomb_fixture tests/memory_bomb_fixture.cpp)
    target_compile_features(execell_memory_bomb_fixture PRIVATE cxx_std_23)
    add_executable(execell_sandbox_memory_test
        tests/sandbox_memory_test.cpp
        src/sandbox/sandbox.cpp
    )
    target_include_directories(execell_sandbox_memory_test PRIVATE ${PROJECT_SOURCE_DIR}/include)
    target_compile_features(execell_sandbox_memory_test PRIVATE cxx_std_23)
    target_compile_options(execell_sandbox_memory_test PRIVATE -Werror)
    add_test(
        NAME sandbox_memory_limit
        COMMAND execell_sandbox_memory_test $<TARGET_FILE:execell_memory_bomb_fixture>
    )

    add_executable(execell_sandbox_escape_test
        tests/sandbox_escape_test.cpp
        src/sandbox/sandbox.cpp
    )
    target_include_directories(execell_sandbox_escape_test PRIVATE ${PROJECT_SOURCE_DIR}/include)
    target_compile_features(execell_sandbox_escape_test PRIVATE cxx_std_23)
    target_compile_options(execell_sandbox_escape_test PRIVATE -Werror)
    add_test(
        NAME sandbox_symlink_escape
        COMMAND execell_sandbox_escape_test
                "ln -s /etc/passwd /tmp/escape && echo bad > /tmp/escape"
    )
    add_test(
        NAME sandbox_relative_escape
        COMMAND execell_sandbox_escape_test
                "echo bad > /tmp/../etc/execell-escape"
    )

    add_executable(execell_parent_death_test
        tests/parent_death_test.cpp
        src/sandbox/sandbox.cpp
    )
    target_include_directories(execell_parent_death_test PRIVATE ${PROJECT_SOURCE_DIR}/include)
    target_compile_features(execell_parent_death_test PRIVATE cxx_std_23)
    target_compile_options(execell_parent_death_test PRIVATE -Werror)
    add_test(NAME parent_death COMMAND execell_parent_death_test)

    add_library(execell_fuzz_boundaries OBJECT tests/fuzz_boundaries.cpp)
    target_include_directories(execell_fuzz_boundaries PRIVATE ${PROJECT_SOURCE_DIR}/include)
    target_compile_features(execell_fuzz_boundaries PRIVATE cxx_std_23)
    target_compile_options(execell_fuzz_boundaries PRIVATE -Werror)

    foreach(test_target IN ITEMS
        execell_fd_table_test
        execell_stop_test
        execell_memory_test
        execell_json_test
        execell_trace_fixture
        execell_network_fixture
        execell_signal_fixture
        execell_exec_fixture
        execell_crash_fixture
        execell_exit_status_fixture
        execell_policy_sandbox_test)
        target_compile_options(${test_target} PRIVATE -Werror)
    endforeach()

    set(EXECELL_TRACE_SUPPORT_SOURCES
        src/sandbox/backend.cpp
        src/trace/tracer.cpp
        src/trace/stop.cpp
        src/trace/architecture.cpp
        src/trace/memory.cpp
        src/trace/syscall.cpp
        src/trace/fd_table.cpp
        src/trace/syscall_decoder.cpp
        src/report/terminal_reporter.cpp
    )
    foreach(sandbox_target IN ITEMS
        execell_aur_test
        execell_package_test
        execell_policy_sandbox_test
        execell_sandbox_isolation_test
        execell_sandbox_cpu_test
        execell_sandbox_memory_test
        execell_sandbox_escape_test
        execell_parent_death_test)
        target_sources(${sandbox_target} PRIVATE ${EXECELL_TRACE_SUPPORT_SOURCES})
    endforeach()
    if(CMAKE_CXX_FLAGS MATCHES "fsanitize=thread")
        # TSan runtime interceptors are incompatible with unprivileged user-namespace setup.
        set_tests_properties(sandbox_trace_events PROPERTIES WILL_FAIL TRUE)
    endif()
endif()
