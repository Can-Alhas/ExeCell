# Phase 2: Reliable Tracer Core

Status: `[x]` complete, `[-]` active, `[ ]` pending.

## Goal

Make ptrace lifecycle, stop handling, task scheduling, signal forwarding, and
cleanup deterministic before adding more syscall decoders.

## Work Items

- [x] Typed stop model: syscall, ptrace event, signal, group stop, exit.
- [x] EINTR-safe `waitpid` wrapper.
- [x] EINTR-safe ptrace wrappers.
- [x] Typed ptrace error model: `ESRCH`, `ECHILD`, `EINTR`.
- [x] `TaskRegistry` owns task state and scheduling.
- [x] `SyscallPhase` replaces boolean entry state.
- [x] Exec event resets syscall phase.
- [x] Child task inherits descriptor state safely.
- [x] Parent-child task identity tracking.
- [x] Signal forwarding policy.
- [x] `PTRACE_O_EXITKILL` cleanup guarantee.
- [x] Root exit status preservation.
- [x] Fast-child-exit handling.
- [x] x86_64 register adapter boundary.
- [x] Trace lifecycle events.
- [x] Stop classification unit tests.
- [x] Fast child integration fixture.
- [x] Signal integration fixture.
- [x] Exec integration fixture.
- [x] Crash and exit-status integration fixtures.
- [x] GCC and Clang build.
- [x] ASan and UBSan test run.
- [x] Zero compiler warnings.

## Implementation Order

1. Typed stop model.
2. Linux wait and ptrace wrappers.
3. Task registry and syscall phase.
4. Trace session cleanup.
5. Signal forwarding.
6. Architecture adapter.
7. Lifecycle events.
8. Unit and integration tests.
9. Sanitizer and warning cleanup.

## Exit Criteria

- Root `ESRCH` never becomes successful trace completion.
- Fast child exit never breaks parent tracing.
- Signals reach tracee exactly once.
- Exec resets syscall phase.
- All trace tasks receive exit events.
- `tracer.cpp` contains orchestration only.
- All Phase 2 tests pass under GCC, Clang, ASan, and UBSan.
