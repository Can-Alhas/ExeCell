#pragma once

#include <execell/core/types.hpp>

#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace execell::trace {

class FdTable {

public:
  using PathReference = std::reference_wrapper<const std::string>;

  void track(int fd, std::string path);
  void track(FileDescriptor fd, std::string path);

  void duplicate(int source_fd, int target_fd);
  void duplicate(FileDescriptor source_fd, FileDescriptor target_fd);

  [[nodiscard]] std::optional<PathReference> lookup(int fd) const noexcept;

  [[nodiscard]] bool contains(int fd) const noexcept;
  [[nodiscard]] bool contains(FileDescriptor fd) const noexcept;

  void close(int fd) noexcept;
  void close(FileDescriptor fd) noexcept;
  void close_range(unsigned first, unsigned last) noexcept;

private:
  std::unordered_map<int, std::string> entries_;
};

} // namespace execell::trace
