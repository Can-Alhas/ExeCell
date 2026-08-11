#include <execell/event/event.hpp>
#include <execell/policy/policy.hpp>
#include <execell/report/json_reporter.hpp>

#include <cstddef>
#include <cstdint>
#include <sstream>
#include <string>
#include <utility>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    const std::string input{reinterpret_cast<const char*>(data), size};
    std::ostringstream output;
    execell::report::JsonReporter reporter{output};
    reporter.report(execell::event::FileOpened{.path = input, .context = {}});
    reporter.finish();

    execell::policy::Engine policy{execell::policy::Config{
        .denied_paths = {"/etc"},
        .denied_endpoints = {},
        .denied_syscalls = {},
        .max_processes = 1
    }};
    (void)policy.evaluate(execell::event::FileOpened{.path = input, .context = {}});
    return 0;
}
