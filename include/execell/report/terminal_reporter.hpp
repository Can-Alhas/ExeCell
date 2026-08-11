#pragma once

#include <execell/event/event.hpp>
#include <execell/report/reporter.hpp>

namespace execell::report {

class TerminalReporter final : public Reporter {
public:
  void report(const event::Event& event) override;
};

} // namespace execell::report
