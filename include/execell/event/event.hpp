#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <sys/types.h>
#include <variant>

namespace execell::event {

struct EventContext {
  pid_t pid{};
  std::uint64_t sequence{};
};

struct FileOpened {
  int fd{};
  std::string path;
  EventContext context;
};

struct FileRead {
  int fd{};
  std::string path;
  std::size_t bytes{};
  EventContext context;
};

struct FileWritten {
  int fd{};
  std::string path;
  std::size_t bytes{};
  EventContext context;
};
struct FileClosed {
  int fd{};
  std::string path;
  EventContext context;
};

struct FileDeleted {
  std::string path;
  EventContext context;
};

struct FileRenamed {
  std::string from;
  std::string to;
  EventContext context;
};

struct DirectoryCreated {
  std::string path;
  EventContext context;
};

struct FileModeChanged {
  std::string path;
  unsigned mode{};
  EventContext context;
};

struct SocketCreated {
  int fd{};
  int domain{};
  int type{};
  int protocol{};
  EventContext context;
};

struct NetworkConnected {
  int fd{};
  std::string endpoint;
  EventContext context;
};

struct NetworkBound {
  int fd{};
  std::string endpoint;
  EventContext context;
};

struct NetworkListening {
  int fd{};
  int backlog{};
  EventContext context;
};

struct NetworkAccepted {
  int fd{};
  std::string endpoint;
  EventContext context;
};

struct SyscallFailed {
  pid_t pid{};
  std::string syscall;
  int error{};
  EventContext context;
};

struct TraceStarted {
  pid_t pid{};
  EventContext context;
};

struct TraceFinished {
  pid_t pid{};
  int status{};
  bool signaled{};
  EventContext context;
};

struct PolicyViolation {
  std::string rule;
  std::string resource;
  EventContext context;
};

struct ProcessSpawned {
  pid_t pid{};
  pid_t parent_pid{};
  EventContext context;
};

struct ProcessExec {
  pid_t pid{};
  std::string path;
  EventContext context;
};

struct ProcessExited {
  pid_t pid{};
  int status{};
  bool signaled{};
  EventContext context;
};

using Event = std::variant<
    FileOpened,
    FileRead,
    FileWritten,
    FileClosed,
    FileDeleted,
    FileRenamed,
    DirectoryCreated,
    FileModeChanged,
    SocketCreated,
    NetworkConnected,
    NetworkBound,
    NetworkListening,
    NetworkAccepted,
    SyscallFailed,
    TraceStarted,
    TraceFinished,
    PolicyViolation,
    ProcessSpawned,
    ProcessExec,
    ProcessExited>;

} // namespace execell::event
