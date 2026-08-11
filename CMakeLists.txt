cmake_minimum_required(VERSION 4.4.2)

project(
	ExeCell
	VERSION 0.1.1
	DESCRIPTION "Linux process inspection and sandboxing toolkit"
	LANGUAGES CXX
)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "ExeCell requires Linux")
endif()

include(CTest)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

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

	src/trace/syscall_decoder.cpp

	src/package/package.cpp
	src/package/rootfs.cpp
	src/package/observation.cpp
	src/package/network.cpp
	src/risk/risk.cpp
)

target_compile_features(execell PRIVATE cxx_std_23)

target_include_directories(execell
	PRIVATE
		${PROJECT_SOURCE_DIR}/include
)

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


if(CMAKE_BUILD_TYPE STREQUAL "Debug")
		    target_compile_options(execell PRIVATE
			   -fsanitize=address,undefined
			   -fno-omit-frame-pointer
                    )

		    target_link_options(execell PRIVATE
		     	   -fsanitize=address,undefined
                    )

endif()

if(BUILD_TESTING)
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
        src/package/rootfs.cpp
        src/package/observation.cpp
        src/sandbox/sandbox.cpp
        src/risk/risk.cpp
        src/package/network.cpp
    )
    target_include_directories(execell_package_test PRIVATE ${PROJECT_SOURCE_DIR}/include)
    target_compile_features(execell_package_test PRIVATE cxx_std_23)
    target_compile_options(execell_package_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME package_subsystem COMMAND execell_package_test)

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
endif()
