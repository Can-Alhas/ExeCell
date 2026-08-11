#include <execell/report/json_reporter.hpp>

#include <type_traits>
#include <string_view>
#include <string>
#include <iomanip>

namespace execell::report {

namespace {

void write_json_string(std::ostream& output, std::string_view value)
{
    output << '"';
    for (const char character : value) {
        switch (character) {
        case '"': output << "\\\""; break;
        case '\\': output << "\\\\"; break;
        case '\n': output << "\\n"; break;
        case '\r': output << "\\r"; break;
        case '\t': output << "\\t"; break;
        default:
            if (static_cast<unsigned char>(character) < 0x20U) {
                output << "\\u00" << std::hex
                       << static_cast<int>(static_cast<unsigned char>(character))
                       << std::dec;
            } else {
                output << character;
            }
        }
    }
    output << '"';
}

} // namespace

void JsonReporter::report(const event::Event& event)
{
    if (finished_) {
        return;
    }
    if (first_) {
        output_ << '[';
        first_ = false;
    } else {
        output_ << ',';
    }

    std::visit([this](const auto& value) {
        using T = std::remove_cvref_t<decltype(value)>;
        std::string_view type = "unknown";
        if constexpr (std::is_same_v<T, event::FileOpened>) type = "file.opened";
        else if constexpr (std::is_same_v<T, event::FileRead>) type = "file.read";
        else if constexpr (std::is_same_v<T, event::FileWritten>) type = "file.written";
        else if constexpr (std::is_same_v<T, event::FileClosed>) type = "file.closed";
        else if constexpr (std::is_same_v<T, event::FileDeleted>) type = "file.deleted";
        else if constexpr (std::is_same_v<T, event::FileRenamed>) type = "file.renamed";
        else if constexpr (std::is_same_v<T, event::DirectoryCreated>) type = "directory.created";
        else if constexpr (std::is_same_v<T, event::SocketCreated>) type = "socket.created";
        else if constexpr (std::is_same_v<T, event::NetworkConnected>) type = "network.connected";
        else if constexpr (std::is_same_v<T, event::NetworkBound>) type = "network.bound";
        else if constexpr (std::is_same_v<T, event::NetworkListening>) type = "network.listening";
        else if constexpr (std::is_same_v<T, event::NetworkAccepted>) type = "network.accepted";
        else if constexpr (std::is_same_v<T, event::SyscallFailed>) type = "syscall.failed";
        else if constexpr (std::is_same_v<T, event::ProcessSpawned>) type = "process.spawned";
        else if constexpr (std::is_same_v<T, event::ProcessExec>) type = "process.exec";
        else if constexpr (std::is_same_v<T, event::ProcessExited>) type = "process.exited";
        else if constexpr (std::is_same_v<T, event::TraceStarted>) type = "trace.started";
        else if constexpr (std::is_same_v<T, event::TraceFinished>) type = "trace.finished";
        else if constexpr (std::is_same_v<T, event::PolicyViolation>) type = "policy.violation";
        output_ << "{\"schema_version\":1,\"type\":";
        write_json_string(output_, type);
        output_ << ",\"pid\":"
                << value.context.pid << ",\"sequence\":"
                << value.context.sequence;
        if constexpr (requires { value.path; }) {
            output_ << ",\"path\":";
            write_json_string(output_, value.path);
        }
        if constexpr (requires { value.bytes; }) {
            output_ << ",\"bytes\":" << value.bytes;
        }
        if constexpr (requires { value.fd; }) {
            output_ << ",\"fd\":" << value.fd;
        }
        if constexpr (requires { value.mode; }) {
            output_ << ",\"mode\":" << value.mode;
        }
        if constexpr (requires { value.endpoint; }) {
            output_ << ",\"endpoint\":";
            write_json_string(output_, value.endpoint);
        }
        if constexpr (requires { value.rule; }) {
            output_ << ",\"rule\":";
            write_json_string(output_, value.rule);
            output_ << ",\"resource\":";
            write_json_string(output_, value.resource);
        }
        if constexpr (requires { value.syscall; }) {
            output_ << ",\"syscall\":\"";
            write_json_string(output_, value.syscall);
            output_ << "\",\"error\":" << value.error;
        }
        if constexpr (requires { value.status; }) {
            output_ << ",\"status\":" << value.status << ",\"signaled\":"
                    << (value.signaled ? "true" : "false");
        }
        if constexpr (requires { value.parent_pid; }) {
            output_ << ",\"parent_pid\":" << value.parent_pid;
        }
        output_ << '}';
    }, event);
}

void JsonReporter::finish()
{
    if (!finished_) {
        output_ << ']';
        finished_ = true;
    }
}

} // namespace execell::report
