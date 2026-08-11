#include <execell/report/terminal_reporter.hpp>

#include <type_traits>
#include <iostream>

namespace execell::report {

void TerminalReporter::report(const event::Event& event)
{
    std::visit(
        [](const auto& value) {
            using EventType = std::remove_cvref_t<decltype(value)>;

            if constexpr (std::is_same_v<EventType, event::FileOpened>) {
                std::cout
                    << "[FILE] OPEN  \""
                    << value.path
                    << "\" fd="
                    << value.fd
                    << '\n';
            }

            else if constexpr (std::is_same_v<EventType, event::FileRead>) {
                std::cout
                    << "[FILE] READ  \""
                    << value.path
                    << "\" bytes="
                    << value.bytes
                    << '\n';
            }

            else if constexpr (std::is_same_v<EventType, event::FileWritten>) {
                std::cout
                    << "[FILE] WRITE \""
                    << value.path
                    << "\" bytes="
                    << value.bytes
                    << '\n';
}

            else if constexpr (std::is_same_v<EventType, event::FileClosed>) {
                std::cout
                    << "[FILE] CLOSE \""
                    << value.path
                    << "\" fd="
                    << value.fd
                     << '\n';
            }

            else if constexpr (std::is_same_v<EventType, event::FileDeleted>) {
                std::cout << "[FILE] DELETE \"" << value.path << "\"\n";
            }

            else if constexpr (std::is_same_v<EventType, event::FileRenamed>) {
                std::cout << "[FILE] RENAME \"" << value.from << "\" -> \""
                          << value.to << "\"\n";
            }

            else if constexpr (std::is_same_v<EventType, event::DirectoryCreated>) {
                std::cout << "[FILE] MKDIR  \"" << value.path << "\"\n";
            }

            else if constexpr (std::is_same_v<EventType, event::FileModeChanged>) {
                std::cout << "[FILE] CHMOD  \"" << value.path << "\" mode="
                          << value.mode << '\n';
            }

            else if constexpr (std::is_same_v<EventType, event::SocketCreated>) {
                std::cout << "[NET] SOCKET fd=" << value.fd
                          << " domain=" << value.domain << '\n';
            }

            else if constexpr (std::is_same_v<EventType, event::NetworkConnected>) {
                std::cout << "[NET] CONNECT " << value.endpoint
                          << " fd=" << value.fd << '\n';
            }

            else if constexpr (std::is_same_v<EventType, event::NetworkBound>) {
                std::cout << "[NET] BIND " << value.endpoint
                          << " fd=" << value.fd << '\n';
            }

            else if constexpr (std::is_same_v<EventType, event::NetworkListening>) {
                std::cout << "[NET] LISTEN fd=" << value.fd
                          << " backlog=" << value.backlog << '\n';
            }

            else if constexpr (std::is_same_v<EventType, event::NetworkAccepted>) {
                std::cout << "[NET] ACCEPT " << value.endpoint
                          << " fd=" << value.fd << '\n';
            }

            else if constexpr (std::is_same_v<EventType, event::SyscallFailed>) {
                std::cout << "[FAIL] " << value.syscall
                          << " errno=" << value.error
                          << " pid=" << value.pid << '\n';
            }

            else if constexpr (std::is_same_v<EventType, event::ProcessSpawned>) {
                std::cout
                    << "[PROC] SPAWN pid=" << value.pid
                    << " parent=" << value.parent_pid << '\n';
            }

            else if constexpr (std::is_same_v<EventType, event::ProcessExec>) {
                std::cout
                    << "[PROC] EXEC  \"" << value.path << "\" pid="
                    << value.pid << '\n';
            }

            else if constexpr (std::is_same_v<EventType, event::ProcessExited>) {
                std::cout
                    << "[PROC] EXIT  pid=" << value.pid
                    << " status=" << value.status
                    << (value.signaled ? " signal" : "") << '\n';
            }

            else if constexpr (std::is_same_v<EventType, event::PolicyViolation>) {
                std::cout << "[POLICY] DENY rule=" << value.rule
                          << " resource=\"" << value.resource << "\"\n";
            }
        },
        event
    );
}

} // namespace execell::report
