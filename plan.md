# ExeCell Development Plan

Status markers: `[x]` baseline complete, `[-]` active, `[ ]` pending.

## Phase 0: Build And Tests

- [x] C++23 build configuration.
- [x] Strict compiler warnings.
- [x] Debug ASan/UBSan.
- [x] CTest enabled.
- [x] FD unit test.
- [x] Tracer integration fixture.
- [x] CI matrix for GCC and Clang.
- [x] clang-tidy baseline.

## Phase 1: Typed System Boundaries

- [x] `std::expected` error model.
- [x] RAII file descriptor wrapper.
- [x] Strong `ProcessId`, `FileDescriptor`, and syscall frame types.
- [x] C API boundaries documented and localized in Linux-facing modules.
- [x] `std::span` command invocation boundary.

## Phase 2: Reliable Tracer Core

- [x] Per-task syscall entry/exit state.
- [x] `waitpid(-1, __WALL)` task collection.
- [x] `PTRACE_O_TRACESYSGOOD`.
- [x] `PTRACE_O_EXITKILL`.
- [x] Clone/fork/vfork ptrace options.
- [x] Signal, syscall, and ptrace stop classification.
- [x] EINTR-safe wait handling.
- [x] Trace cleanup with `PTRACE_O_EXITKILL`.
- [x] Explicit x86_64 architecture boundary.

## Phase 3: File Descriptor And Path Model

- [x] `FdTable` ownership of descriptor mappings.
- [x] `dup`, `dup2`, `dup3` mapping support.
- [x] `fcntl(F_DUPFD*)` support.
- [x] `close_range` support.
- [x] Inherited descriptor behavior remains unknown-safe.
- [x] `AT_FDCWD` and `dirfd` resolution.
- [x] Relative path normalization.
- [x] Bounded process-memory reads with failure-safe empty result.

## Phase 4: Filesystem Observation

- [x] `openat`, `read`, `write`, `close` events.
- [x] `open`, `openat2`.
- [x] `pread`, `pwrite`, vectored I/O descriptor tracking.
- [x] `unlink`, `unlinkat`.
- [x] `rename`, `renameat`.
- [x] `renameat2`.
- [x] `mkdir`, `mkdirat`.
- [x] `chmod`.
- [x] `fchmod`, `fchmodat`.
- [x] Failed operation metadata for tracked operations.
- [x] Filesystem integration fixtures.

## Phase 5: Process Observation

- [x] Process spawn event.
- [x] Process exit event.
- [x] Exec event.
- [x] `PTRACE_EVENT_EXEC` handling.
- [x] Parent-child identity model.
- [x] Complete descendant lifecycle fixture.

## Phase 6: Network Observation

- [x] Socket event descriptor model.
- [x] `socket`.
- [x] `connect`.
- [x] `bind`.
- [x] `listen`.
- [x] `accept`, `accept4`.
- [x] IPv4 and IPv6 decoding.
- [x] Unix socket decoding.
- [x] Failed network event metadata for connect/bind.

## Phase 7: Event Pipeline

- [x] `std::variant` event model.
- [x] Common event context: pid, sequence.
- [x] Reporter sink interface.
- [x] Independent terminal reporter.
- [x] Summary collector.
- [x] JSON reporter boundary.

## Phase 8: Inspect Command

- [x] Typed CLI invocation boundary.
- [x] `execell inspect`.
- [x] File counters.
- [x] Process counters.
- [x] Network counters.
- [x] Failure counters.
- [x] Summary integration test.

## Phase 9: Policy Engine

- [x] Policy value model.
- [x] Path allow/deny rules.
- [x] Network destination rules.
- [x] Syscall rules.
- [x] Process/resource limit model.
- [x] Explainable violations.
- [x] Policy unit tests.

## Phase 10: Sandbox

- [x] Sandbox configuration validation.
- [x] Namespace lifecycle scoped to sandbox child process.
- [x] User namespace.
- [x] Mount namespace.
- [x] Isolated temporary filesystem.
- [x] Capability drop.
- [x] Resource limits.
- [x] `no_new_privileges` enforcement.
- [x] Network namespace policy.
- [x] Sandbox validation/cleanup tests.

## Phase 11: Release Quality

- [x] GCC and Clang builds.
- [x] Debug sanitizer integration.
- [x] Static analysis configuration and smoke run.
- [x] Documentation for Linux requirements.
- [x] Versioned CLI behavior.
- [x] Security threat model.
