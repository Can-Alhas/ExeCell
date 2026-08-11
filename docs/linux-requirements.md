# Linux Requirements

ExeCell targets Linux x86_64.

- C++23 compiler: GCC 13+ or Clang 17+.
- CMake 4.4.2 or newer.
- `ptrace` permission for trace targets.
- `CONFIG_USER_NS` for `sandbox` user namespaces.
- Mount namespace support for isolated `/tmp`.
- Network namespace support for network isolation.
- `libarchive` for in-process package archive parsing.
- SQLite3 for baseline and version-delta storage.
- Optional delegated cgroup v2 subtree for `--cgroup-root` budgets.

Sandbox setup can fail when host policy disables unprivileged namespaces.
ExeCell exits before executing target when setup fails.

Package scans reject hosts without Btrfs-backed rootfs isolation. Privileged package
scanning is disabled. AUR builds additionally require an isolated rootfs containing
`makepkg` and its runtime dependencies.

Configured cgroup budgets fail closed when cgroup files cannot be written.
Without `--cgroup-root`, per-process `RLIMIT_*` limits remain active.
