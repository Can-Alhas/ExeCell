# ExeCell Package Scanner Roadmap

Status: `[x]` complete, `[-]` active, `[ ]` pending.

## Product Goal

ExeCell scans Arch packages before host installation.

```text
package
  -> verify
  -> ephemeral rootfs
  -> pacman install
  -> observe scripts/hooks
  -> filesystem/process/network diff
  -> executable smoke scans
  -> risk score
  -> install verdict
```

Host filesystem remains unchanged.

## Operating Modes

- [ ] Rootless mode: user namespace, sandbox UID 0, no host root.
- [ ] Rootful mode: explicit privileged mode for complete package semantics.
- [ ] Rootless default.
- [ ] Rootful mode warning and confirmation.
- [ ] Separate security profiles for rootless/rootful execution.

## CLI

- [ ] `execell package scan <package>`.
- [ ] `execell package fetch <package>`.
- [ ] `execell package report <session>`.
- [ ] `execell package cleanup`.
- [ ] `--privileged`.
- [ ] `--timeout 30s`.
- [ ] `--network off|mirror`.
- [ ] `--run-all`.
- [ ] `--byte-diff`.
- [ ] `--format terminal|json|jsonl`.
- [ ] `--rootfs <path>`.

## Phase 1: Arch Package Adapter

- [ ] Detect `pkg.tar.*` packages.
- [ ] Read package metadata.
- [ ] Validate `x86_64` architecture.
- [ ] Read dependency list.
- [ ] Read payload file list.
- [ ] Read maintainer scripts.
- [ ] Read install hooks.
- [ ] Reject corrupt archive.
- [ ] Reject unsupported architecture.
- [ ] Reject invalid signature.

## Phase 2: Signature Verification

- [ ] Mandatory signature verification.
- [ ] Scan-specific temporary keyring.
- [ ] Explicit trusted-key import.
- [ ] Signature result event.
- [ ] Fail-closed verification errors.
- [ ] Signature fixture matrix.

## Phase 3: Btrfs Rootfs Builder

- [ ] Detect Btrfs source filesystem.
- [ ] Create read-only source snapshot.
- [ ] Create per-session writable snapshot.
- [ ] Unique session ID.
- [ ] RAII snapshot cleanup.
- [ ] Cleanup after crash.
- [ ] Cleanup after SIGTERM.
- [ ] Snapshot quota/size limit.
- [ ] Rootless capability detection.
- [ ] Rootful capability path.
- [ ] Non-Btrfs fallback policy.

## Phase 4: Pacman Sandbox

- [ ] Prepare ephemeral rootfs.
- [ ] Run `pacman -U` inside rootfs.
- [ ] Isolate package database.
- [ ] Isolate package cache.
- [ ] Mount scan-specific keyring.
- [ ] Read-only host libraries.
- [ ] Writable ephemeral `/tmp`.
- [ ] Writable ephemeral `/var`.
- [ ] Network disabled by default.
- [ ] Optional mirror allowlist.
- [ ] Capability drop.
- [ ] `no_new_privileges`.
- [ ] Seccomp profile.
- [ ] CPU limit.
- [ ] Memory limit.
- [ ] Process limit.
- [ ] File-size limit.
- [ ] Wall-clock timeout: 30 seconds.

## Phase 5: Maintainer Script Observation

- [ ] Execute maintainer scripts.
- [ ] Trace script processes.
- [ ] Capture bounded stdout.
- [ ] Capture bounded stderr.
- [ ] Trace pacman hooks.
- [ ] Detect service activation.
- [ ] Detect privilege changes.
- [ ] Detect capability changes.
- [ ] Detect persistence attempts.
- [ ] Generate script lifecycle events.

## Phase 6: Filesystem Diff

- [ ] Created paths.
- [ ] Modified paths.
- [ ] Deleted paths.
- [ ] Mode changes.
- [ ] Ownership changes.
- [ ] setuid/setgid changes.
- [ ] File capabilities.
- [ ] Symlink changes.
- [ ] Hardlink changes.
- [ ] Optional byte-level diff.
- [ ] Before/after hashes.
- [ ] Size and metadata diff.

## Phase 7: Executable Smoke Scan

- [ ] Detect ELF binaries.
- [ ] Detect executable scripts.
- [ ] Resolve executable symlinks.
- [ ] Run every executable in separate sandbox.
- [ ] Default no-argument execution.
- [ ] 30-second timeout per executable.
- [ ] CPU/memory/process/file limits.
- [ ] Capture stdout/stderr.
- [ ] Trace filesystem behavior.
- [ ] Trace process tree.
- [ ] Trace network behavior.
- [ ] Capture exit status.
- [ ] Bounded concurrency.
- [ ] Default worker limit: 4.
- [ ] Global resource budget.

## Phase 8: Risk Engine

- [ ] Risk levels: none, low, medium, high, critical.
- [ ] Weighted event rules.
- [ ] Host escape detection.
- [ ] Privilege escalation score.
- [ ] Network access score.
- [ ] Service activation score.
- [ ] Persistence score.
- [ ] Sensitive-read score.
- [ ] Process explosion score.
- [ ] Resource violation score.
- [ ] Explainable risk factors.
- [ ] Verdicts: allow, audit, reject.
- [ ] Critical event direct reject.
- [ ] Signature failure direct reject.
- [ ] Architecture mismatch direct reject.

## Phase 9: Network Policy

- [ ] Network off default.
- [ ] Separate download phase.
- [ ] Mirror allowlist.
- [ ] Controlled DNS.
- [ ] Arbitrary IP deny.
- [ ] Destination/port/protocol events.
- [ ] Package phase network report.
- [ ] Executable phase network report.

## Phase 10: Reports

- [ ] Session artifact directory.
- [ ] `metadata.json`.
- [ ] `summary.json`.
- [ ] `events.jsonl`.
- [ ] `filesystem.json`.
- [ ] `processes.json`.
- [ ] `network.json`.
- [ ] `risk.json`.
- [ ] Captured stdout.
- [ ] Captured stderr.
- [ ] Stable report schema version.
- [ ] Terminal summary.
- [ ] Bounded streaming output.

## Phase 11: Security Fixtures

- [ ] Valid signed package.
- [ ] Invalid signature.
- [ ] Wrong architecture.
- [ ] Corrupt archive.
- [ ] Script file creation.
- [ ] Script service start.
- [ ] Script privilege attempt.
- [ ] Config modification.
- [ ] setuid payload.
- [ ] Persistence attempt.
- [ ] Mirror connection.
- [ ] Arbitrary endpoint connection.
- [ ] Fork/process explosion.
- [ ] Timeout.
- [ ] Memory limit.
- [ ] Rootfs escape.
- [ ] Symlink escape.
- [ ] Relative path escape.
- [ ] Parent death.
- [ ] Snapshot cleanup.

## Phase 12: Release Quality

- [ ] GCC build.
- [ ] Clang build.
- [ ] ASan.
- [ ] UBSan.
- [ ] `-Werror`.
- [ ] Rootless matrix.
- [ ] Rootful matrix.
- [ ] Reproducible scan session.
- [ ] Security threat model update.
- [ ] Arch adapter documentation.
- [ ] Rootful warning documentation.
- [ ] Rootless limitation documentation.
- [ ] Session retention policy.

## Milestones

### M0: Arch Local Package Audit

- [ ] Local `.pkg.tar.*` input.
- [ ] Mandatory signature verification.
- [ ] Ephemeral rootfs.
- [ ] `pacman -U`.
- [ ] Maintainer script tracing.
- [ ] Filesystem diff.
- [ ] Process tree.
- [ ] Network off.
- [ ] 30-second timeout.
- [ ] Risk summary.
- [ ] Terminal and JSON report.
- [ ] Rootless/rootful modes.
- [ ] Cleanup guarantee.

### M1: Executable Smoke Scan

- [ ] ELF/script discovery.
- [ ] Separate sandbox per executable.
- [ ] No-argument run.
- [ ] Timeout and resource limits.
- [ ] Bounded concurrency.
- [ ] Per-executable artifact report.

### M2: Network And Risk Enforcement

- [ ] Mirror allowlist.
- [ ] Network risk rules.
- [ ] Weighted risk score.
- [ ] Allow/audit/reject verdict.
- [ ] Critical event enforcement.

## Acceptance

- [ ] Host filesystem unchanged after scan.
- [ ] Invalid signature never installs.
- [ ] Non-x86_64 package rejected.
- [ ] Maintainer scripts fully observed.
- [ ] Every executable gets bounded isolated run.
- [ ] Filesystem/process/network diff generated.
- [ ] Risk verdict explainable.
- [ ] Rootless and rootful modes tested.
- [ ] GCC/Clang + sanitizers + `-Werror` clean.
- [ ] Security fixture matrix passes.
