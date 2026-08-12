# ExeCell Development Status

## Current Version

`0.2.0` - Analyze Runtime Hardening

## Current Capability

ExeCell observes Linux programs with ptrace, applies path/endpoint/syscall and
process policies, runs bounded namespace sandbox sessions, analyzes local Arch
packages, and writes explainable session reports.

Primary workflow:

```sh
./build-manual/execell analyze \
  --format json \
  --timeout 30 \
  --output-limit 1048576 \
  --sandbox \
  PROGRAM ARGUMENTS...
```

Session artifacts live under `/tmp/execell-session-*`:

- `events.json`
- `summary.json`
- `attestation.txt` for sandbox analyses

## Completed Milestones

- Trace, inspect, sandbox, and package CLI paths.
- Rootless package scanner and Btrfs rootfs capability checks.
- `analyze` library extracted from `main.cpp`.
- Terminal and JSON analyze output, schema version 2.
- Stable finding IDs with observed/policy finding separation.
- Policy resource and event context for policy findings.
- Timeout and combined stdout/stderr output limits.
- Process-group cleanup after timeout or output overflow.
- Sandbox attestation in analysis session output.
- Manual harmless risk fixture.
- 32-test CTest security matrix; Arch+Btrfs acceptance skips when fixture absent.

## Next Coding Tasks

1. Feed sandbox ptrace events into the same analyze policy event stream.
2. Attach source event context to aggregate observed findings.
3. Add explicit finding resource/context schema tests.
4. Add `coverage` and `confidence` fields to attestation/report output.
5. Add deterministic JSONL and SQLite report consistency tests.

## Infrastructure-Gated Tasks

These are not marked complete without required environments:

- Real Arch+Btrfs acceptance host with `pacman`, `makepkg`, `gpgv`, and keyring.
- Firecracker/QEMU VM backend and lifecycle tests.
- Controlled DNS and egress allowlist test network.
- Reproducible package fixture repository.
- Self-hosted Arch CI runner with namespace, cgroup, Btrfs, and sanitizer jobs.

## Security Boundary

ExeCell is an observation and containment tool, not a complete malware
detector. Kernel vulnerabilities, privileged helpers, runtime compromise, and
unsupported host policies remain outside its guarantees. Untrusted packages
require a dedicated VM or host until VM isolation is implemented.

## Verification

```sh
cmake -S . -B build-manual -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build-manual -j2
ctest --test-dir build-manual --output-on-failure
```
