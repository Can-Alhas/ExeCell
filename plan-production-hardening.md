# Production Security Hardening

Status: `[x]` complete, `[-]` active, `[ ]` pending.

## Policy Enforcement

- [x] Policy engine consumes event stream.
- [x] Path allow/deny enforcement.
- [x] Network endpoint enforcement.
- [x] Syscall enforcement for observed failed syscalls.
- [x] Process limit enforcement.
- [x] Explainable violations with event context.
- [x] Fail-closed policy errors.

## Seccomp

- [x] Typed seccomp profile.
- [x] x86_64 architecture validation.
- [x] Allowlist builder.
- [x] `PR_SET_NO_NEW_PRIVS` ordering.
- [x] BPF installation.
- [x] Blocked syscall tests.
- [x] Profile setup failure prevents target execution.

## Sandbox Hardening

- [x] RAII sync pipe ownership.
- [x] EINTR-safe sandbox waits.
- [x] Partial write handling.
- [x] Namespace setup error propagation baseline.
- [x] Mount propagation error handling baseline.
- [x] Capability drop error handling baseline.
- [x] Resource limit validation.
- [x] Parent-death cleanup.
- [x] Host filesystem side-effect tests.

## CLI And JSON

- [x] Typed CLI options.
- [x] `trace --format json`.
- [x] `inspect --format terminal|json`.
- [x] `inspect --deny-path` policy option.
- [x] Sandbox resource options.
- [x] Valid closed JSON output.
- [x] JSON string escaping.
- [x] Complete event payload output baseline.
- [x] Exit status categories baseline: tracee, policy, sandbox, CLI failure paths.

## Security Tests

- [x] Path deny fixture.
- [x] Network deny fixture.
- [x] Process limit fixture.
- [x] CPU limit fixture.
- [x] Memory limit fixture.
- [x] Seccomp deny fixture.
- [x] Read-only root mount protection.
- [x] Symlink escape fixture.
- [x] Relative path escape fixture.
- [x] Malformed memory/path boundary tests.
- [x] Parent death fixture.
- [x] Fuzzable decoder boundaries.

## Final Acceptance

- [x] GCC and Clang build.
- [x] ASan and UBSan.
- [x] `-Werror`.
- [x] CTest security matrix baseline.
- [x] Valid JSON validation.
- [x] Updated threat model.
