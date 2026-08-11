#include <execell/report/json_reporter.hpp>

#include <cassert>
#include <sstream>

int main()
{
    std::ostringstream output;
    {
        execell::report::JsonReporter reporter{output};
        reporter.report(execell::event::FileOpened{
            .fd = 3,
            .path = "quote\"newline\n",
            .context = {.pid = 7, .sequence = 1}
        });
        reporter.finish();
        reporter.finish();
    }
    const auto json = output.str();
    assert(json.front() == '[');
    assert(json.back() == ']');
    assert(json.find("quote\\\"newline\\n") != std::string::npos);
}
