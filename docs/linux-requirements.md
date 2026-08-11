# Linux Requirements

ExeCell targets Linux x86_64.

- C++23 compiler: GCC 13+ or Clang 17+.
- CMake 4.4.2 or newer.
- `ptrace` permission for trace targets.
- `CONFIG_USER_NS` for `sandbox` user namespaces.
- Mount namespace support for isolated `/tmp`.
- Network namespace support for network isolation.

Sandbox setup can fail when host policy disables unprivileged namespaces.
ExeCell exits before executing target when setup fails.
