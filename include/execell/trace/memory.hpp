#pragma once

#include <string>
#include <cstddef>
#include <sys/types.h>

namespace execell::trace {

enum class MemoryReadStatus { complete, truncated, invalid_address };

struct MemoryRead {
  std::string value;
  MemoryReadStatus status{MemoryReadStatus::complete};
  std::size_t bytes{};

};

[[nodiscard]] MemoryRead read_process_memory_string(pid_t pid, unsigned long address);
[[nodiscard]] std::string read_process_string_value(pid_t pid, unsigned long address);

} // namespace execell::trace
