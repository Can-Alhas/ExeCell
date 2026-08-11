# ExeCell Package Risk Intelligence Roadmap

Status: core implementation delivered. Host-dependent runtime acceptance requires
Btrfs rootfs, Arch keyring, and rootless namespace support.

## Mission

Scan accepted Arch Linux and AUR packages before installation. Detect supply-chain
risk, package behavior, and behavior changes across package versions without
exposing host to package-provided code.

AI is out of scope for scanner decisions. Future AI integration may consume
finished reports only.

## Security Boundary

- Scanner runs fully rootless.
- Package contents, `PKGBUILD`, build scripts, hooks, binaries, dependencies,
  and downloaded sources are untrusted at execution boundaries.
- Valid signature proves provenance or key authorization, not safe behavior.
- Host filesystem, descriptors, credentials, environment, processes, and network
  remain inaccessible.
- Sandbox setup failure is fatal. Scanner never continues unsandboxed.
- Missing Btrfs isolation rejects scan for now.
- Kernel, runtime, and host compromise remain outside guarantees; stronger VM
  isolation is future work.

## Milestone M0: Fail-Closed Sandbox

- Enforce rootless-only operation.
- Reject privileged package scan paths.
- Reject degraded rootfs mode.
- Require user, mount, and network namespace setup as configured.
- Audit inherited file descriptors and environment.
- Use process groups or pidfds for complete descendant cleanup.
- Make timeout and cancellation kill complete task trees.
- Apply seccomp profiles to package, build, script, and executable phases.
- Add setup-failure and descendant-cleanup tests.

## Milestone M1: Safe Package Adapter

- Support `.pkg.tar.*` archives.
- Parse archive metadata without unsafe host-side extraction.
- Verify signatures in isolated, scan-specific trust context.
- Enforce package size, entry count, path length, and decompression budgets.
- Reject absolute paths, traversal, unsafe symlinks, hardlinks, devices, FIFOs,
  sockets, setuid, setgid, and unexpected capabilities as policy requires.
- Use descriptor-relative, race-resistant staging.
- Record package and payload hashes.
- Capture ownership, mode, xattr, capability, symlink, and hardlink metadata.

## Milestone M2: Rootless Arch Runtime

- Build immutable base rootfs.
- Create per-scan writable filesystem layers.
- Isolate package database, cache, `/var`, `/tmp`, and build workspace.
- Expose only required runtime files.
- Keep `/proc`, `/sys`, `/dev`, and `/run` isolated or minimal.
- Run `pacman` only inside sandbox.
- Run maintainer scripts and hooks inside sandbox.
- Keep normal package scans network-disabled.

## Milestone M3: AUR Build Pipeline

- Parse `PKGBUILD` statically.
- Separate source download, prepare, build, check, and package phases.
- Run every phase in separate or resettable rootless sandboxes.
- Restrict source download network to explicit policy.
- Record URL, redirect, host, hash, Git revision, and downloaded artifacts.
- Prevent host environment, credentials, SSH agents, and arbitrary descriptors.
- Validate produced package through M1 before installation simulation.

## Milestone M4: Behavioral Observation

- Run every maintainer script and hook independently.
- Run executable smoke tests in independent sandboxes.
- Use bounded stdout, stderr, CPU, memory, process, file, and wall-clock budgets.
- Observe syscall, filesystem, process, exec, signal, and network events.
- Detect sensitive reads, persistence, service activation, privilege attempts,
  capability changes, unexpected interpreters, and downloader behavior.
- Distinguish observed absence from incomplete coverage.

## Milestone M5: Bounded Parallel Scheduler

- Use `std::jthread` and `std::stop_token`.
- Assign each package independent resource budget.
- Bound worker count and global host resource usage.
- Return unused package budget after task completion.
- Propagate cancellation and timeout deterministically.
- Keep session ownership and cleanup RAII-based.
- Prevent one package from starving others.

## Milestone M6: SQLite Baseline

- Add schema versioning and migrations.
- Store package identity, signature, source revision, dependency fingerprint,
  package hash, and build options.
- Store normalized static and dynamic events.
- Store filesystem, process, network, syscall, and executable fingerprints.
- Compare same package name across versions.
- Compare source commits and dependency changes.
- Mark first observation as baseline, not suspicious.
- Preserve raw evidence for every derived finding.

## Milestone M7: Explainable Risk Engine

- Combine static, build, install, and runtime findings.
- Use direct reject rules for signature, architecture, archive, and isolation
  failures.
- Use weighted scores only as secondary prioritization.
- Report risk level, action, confidence, and coverage.
- Report version deltas with evidence and explanations.
- Keep `allow`, `audit`, and `reject` deterministic.

## Milestone M8: Defensive Fixture Matrix

Fixtures must be bounded, owned, and harmless outside sandbox.

- Valid signed official-style package.
- Valid signed local package.
- AUR `PKGBUILD` fixture.
- Invalid and missing signatures.
- Wrong architecture and corrupt archive.
- Traversal, symlink, hardlink, device, and unsafe metadata archives.
- Maintainer script and hook file creation.
- Service, timer, cron, and persistence attempts.
- Sensitive path read attempt.
- Network and arbitrary endpoint attempts.
- setuid, setgid, and capability attempts.
- Child-process explosion, CPU, memory, output, and timeout fixtures.
- Parent death and descendant cleanup.
- Version pair with controlled behavior change.
- SQLite migration, interruption, and recovery tests.

## Verification Gates

- Host filesystem unchanged after every scan.
- No package code executes before sandbox completion.
- No privileged path exists in normal CLI behavior.
- No execution continues after sandbox setup failure.
- No descendant remains after timeout or cancellation.
- Network policy is observable and enforced.
- Reports remain valid under malformed package output.
- GCC, Clang, ASan, UBSan, and focused concurrency checks pass.

## Implementation Order

1. M0 sandbox fail-closed changes.
2. M1 archive and staging boundary.
3. Defensive package fixtures.
4. M2 rootless Arch runtime.
5. M3 AUR build pipeline.
6. M4 observation expansion.
7. M5 scheduler.
8. M6 SQLite baseline.
9. M7 risk and report integration.
10. M8 full acceptance matrix.

## Delivered Components

- Rootless-only CLI and fail-closed Btrfs requirement.
- Process-group cleanup, parent-death handling, bounded output, clean environment,
  resource limits, and package seccomp profile.
- In-process libarchive parser with bounded paths, entries, decompression, links,
  special-file rejection, and race-resistant staging.
- Isolated read-only `gpgv` signature verification boundary.
- Rootless pacman and multi-phase makepkg execution paths.
- Static AUR manifest parser and suspicious-construct findings.
- Explicit AUR source-host allowlist validation.
- Bounded parallel observation workers with per-task and global package budgets.
- Optional in-sandbox ptrace event stream for package observations.
- Btrfs runtime `/proc` and `/run` mounts with clean environment.
- Filesystem mode, ownership, symlink, and content-hash diff fields.
- SQLite schema, migrations, raw events, baselines, and version comparison CLI.
- Version deltas feed risk score and verdict.
- Optional delegated cgroup v2 budgets fail closed when configured.
- Arch/Btrfs acceptance test skips safely when host fixture unavailable.

## Residual Host-Dependent Work

- Real Arch+Btrfs acceptance requires host fixture containing `pacman`, `makepkg`,
  keyring, and runtime dependencies. Test skips when `EXECELL_ARCH_ROOTFS` absent.
- VM isolation backend remains optional future defense for kernel/runtime compromise;
  no VM runtime exists in current host.
- Archive, AUR, package, sandbox, storage, GCC, Clang, and sanitizer tests.

## Advanced Roadmap A0-A10

### A0: Real Acceptance Host

- Dedicated Arch Linux+Btrfs acceptance host.
- Rootless namespace and cgroup capability matrix.
- `pacman`, `makepkg`, `gpgv`, and Arch keyring fixture.
- `EXECELL_ARCH_ROOTFS` acceptance fixture.
- GCC, Clang, ASan, UBSan, and TSan CI.
- Reproducible package fixture repository.

### A1: VM Isolation Backend

- Add `IsolationBackend` interface.
- Separate `namespace` and `vm` backends.
- Use Firecracker as primary VM backend.
- Use QEMU/KVM fallback.
- Reject scan when requested VM backend unavailable.
- Never silently downgrade VM isolation to namespaces.
- Read-only VM base image.
- Ephemeral writable VM disk.
- pidfd-managed VM lifecycle.
- VM timeout, poweroff, and cleanup.
- Host/guest event transport.
- VM escape acceptance fixtures.

### A2: Isolation Attestation

- Record sandbox startup manifest.
- Record kernel, namespace, seccomp, capability, and cgroup state.
- Record rootfs and runtime-policy hashes.
- Audit inherited host descriptors and environment.
- Audit network interfaces and routes.
- Add attestation object to every report.
- Add `coverage` and `confidence` fields.
- Represent missing controls as `unknown`, never safe.

### A3: Real Network Policy

- Separate source-download sandbox.
- Controlled DNS resolver or static resolution.
- Hostname allowlist.
- IP, port, and protocol allowlist.
- Redirect host revalidation.
- DNS rebinding protection.
- Network namespace interface lifecycle.
- Egress event capture.
- Offline default.
- Mirror hash and provenance records.

### A4: Package Intelligence

- Static package metadata fingerprints.
- ELF Build ID, SONAME, imported-symbol, and interpreter fingerprints.
- Script and hook classification.
- Sensitive-path classification.
- Persistence classification.
- Version behavior delta graph.
- Dependency graph delta.
- First-seen, changed, reverted, and unknown states.
- SQLite schema v2 migration.
- Evidence-to-finding foreign keys.

### A5: Reproducible Build Analysis

- Repeat same `PKGBUILD` and source in isolated sessions.
- Compare artifact hashes.
- Record build environment fingerprint.
- Record compiler and toolchain fingerprint.
- Record build network behavior.
- Detect nondeterministic files.
- Verify source archive hashes.
- Verify Git commit and tag identity.
- Treat rebuild mismatch as high-risk finding.

### A6: Scheduler V2

- Per-package cgroup subtree.
- Global CPU, memory, process, and output budget.
- Fair queue.
- Risk and package-size priority.
- `stop_token` plus pidfd cancellation.
- Budget refund after task completion.
- Worker crash recovery.
- Persistent job state.
- Interrupted-scan resume.
- Starvation tests.

### A7: Behavioral Coverage

- Separate rootfs per executable.
- Separate install, script, hook, build, and smoke sessions.
- Syscall event normalization.
- Filesystem event normalization.
- Network event normalization.
- Coverage states: static-only, executed, timed out, rejected, dependency-unavailable.
- Distinguish not-observed from absent.
- Detect trace loss.

### A8: Risk Engine V2

- Static risk score.
- Build risk score.
- Install risk score.
- Runtime risk score.
- Version-delta score.
- Reproducibility score.
- Coverage confidence.
- Direct reject rules.
- Evidence-linked explainable findings.
- Deterministic JSON schema v2.
- Terminal, JSON, JSONL, and SQLite consistency tests.

### A9: Defensive Corpus

- Signed official package.
- Signed local package.
- AUR package.
- Malicious maintainer-script fixture.
- Hook persistence fixture.
- Downloader fixture.
- Sensitive-read fixture.
- Capability and setuid fixture.
- Archive traversal, link, and device fixtures.
- Nondeterministic-build fixture.
- Version behavior-change pair.
- VM escape-attempt fixture.
- Resource-exhaustion fixture.
- Network-policy bypass fixture.

### A10: Release Security

- TSan verification.
- libFuzzer archive and parser fuzzing.
- SQLite corruption and recovery tests.
- Kernel matrix.
- Arch namespace-policy matrix.
- Dedicated acceptance-host run.
- Reproducible release artifacts.
- SBOM generation.
- Signed release binaries.
- Threat-model update.
- Security disclosure policy.
- No kernel-isolation claim without VM backend.
- TSan namespace limitation is documented; incompatible sandbox test is marked
  expected-failure instead of being reported as a false pass.

### Advanced Execution Order

1. A0: Real Acceptance Host.
2. A1: VM Isolation Backend.
3. A2: Isolation Attestation.
4. A3: Real Network Policy.
5. A4: Package Intelligence.
6. A5: Reproducible Build Analysis.
7. A6: Scheduler V2.
8. A7: Behavioral Coverage.
9. A8: Risk Engine V2.
10. A9: Defensive Corpus.
11. A10: Release Security.

### Advanced Status

- [x] A0 acceptance capability matrix and `package doctor`.
- [x] A1 explicit VM backend boundary and fail-closed selection.
- [x] A2 isolation attestation manifest.
- [x] A3 source host/hash/network policy records.
- [x] A4 package and ELF fingerprints.
- [x] A5 repeated-build reproducibility comparison.
- [x] A6 cgroup budgets and worker recovery.
- [x] A7 coverage states and confidence.
- [x] A8 report schema v2 and deterministic risk output.
- [x] A9 defensive archive/AUR/resource corpus expansion.
- [x] A10 GCC, Clang, ASan, UBSan, TSan, and full CTest verification.

### Post-A10 Hardening Delivered

- Optional Clang libFuzzer archive path/link harness.
- Release verification script with clean Release build, CTest, diff check,
  and executable SBOM hash manifest.
- VM backend availability detection and explicit no-downgrade failure.
