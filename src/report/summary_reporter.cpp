#include <execell/report/summary_reporter.hpp>

#include <iostream>
#include <type_traits>

namespace execell::report {

void Summary::report(const event::Event& event)
{
    std::visit([this](const auto& value) {
        using T = std::remove_cvref_t<decltype(value)>;
        if constexpr (std::is_same_v<T, event::FileOpened>) {
            ++files_opened;
        } else if constexpr (std::is_same_v<T, event::FileRead>) {
            ++files_read;
        } else if constexpr (std::is_same_v<T, event::FileWritten>) {
            ++files_written;
        } else if constexpr (std::is_same_v<T, event::ProcessSpawned>) {
            ++processes_spawned;
        } else if constexpr (
            std::is_same_v<T, event::NetworkConnected> ||
            std::is_same_v<T, event::NetworkBound> ||
            std::is_same_v<T, event::NetworkAccepted>) {
            ++network_attempts;
        } else if constexpr (std::is_same_v<T, event::SyscallFailed>) {
            ++failures;
        }
    }, event);
}

void Summary::print(std::ostream& output) const
{
    output << "ExeCell Inspection Report\n"
           << "Files opened: " << files_opened << '\n'
           << "Files read: " << files_read << '\n'
           << "Files written: " << files_written << '\n'
           << "Processes spawned: " << processes_spawned << '\n'
           << "Network attempts: " << network_attempts << '\n'
           << "Failures: " << failures << '\n';
}

} // namespace execell::report
