# ExeCell

ExeCell is a Linux x86_64 process inspection and package-audit toolkit written in modern C++23.
It traces untrusted programs, applies sandbox policies, and audits Arch Linux packages before
installation.

## What It Does

- Traces file, process, syscall, and network activity with `ptrace`.
- Runs programs inside user and mount namespaces.
- Drops capabilities and enables `no_new_privileges`.
- Provides optional network namespaces, CPU, memory, process, and file-size limits.
- Detects Arch package metadata, dependencies, payload paths, scripts, hooks, and executables.
- Rejects invalid signatures, unsupported architectures, corrupt archives, and unsafe archive paths.
- Builds temporary rootfs sessions with Btrfs snapshot support when available.
- Observes package scripts and executable smoke runs inside isolated sessions.
- Produces filesystem, process, network, event, and explainable risk reports.

ExeCell does not install anything on host by default. Rootful package execution requires explicit
`--privileged --yes` confirmation.

## Requirements

- Linux x86_64
- GCC 13+ or Clang 17+
- CMake 4.4.2+
- Linux user, mount, and network namespace support
- `tar` for local package inspection
- `pacman-key` and detached `.sig` file for signature verification
- `pacman` and a suitable rootfs for rootful package installation

See [`docs/linux-requirements.md`](docs/linux-requirements.md).

## Build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build -j2
ctest --test-dir build --output-on-failure
```

Debug builds enable AddressSanitizer and UndefinedBehaviorSanitizer:

```sh
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
cmake --build build-asan -j2
ctest --test-dir build-asan --output-on-failure
```

## Process Inspection

Run a program:

```sh
./build/execell run /bin/true
```

Trace events in terminal or JSON:

```sh
./build/execell trace /bin/true
./build/execell trace --format json /bin/true
```

Apply policy checks:

```sh
./build/execell inspect --format json /bin/true
./build/execell inspect --deny-path /etc /bin/cat /etc/hosts
```

## Sandbox

Sandbox execution is transparent: target stdout, stderr, and exit status remain target-owned.
Isolation can be verified with:

```sh
./build/execell sandbox /bin/sh -c 'id; grep -E "NoNewPrivs|CapEff" /proc/self/status'
./build/execell sandbox --network /bin/sh -c 'cat /proc/1/net/dev'
./build/execell sandbox /bin/sh -c 'touch /etc/execell-test'
```

The last command must fail with a read-only filesystem error.

## Package Scanner

Rootless local scan:

```sh
./build/execell package scan \
  --format terminal \
  --network off \
  --timeout 30s \
  /path/to/package.pkg.tar.zst
```

The detached signature must be adjacent:

```text
package.pkg.tar.zst
package.pkg.tar.zst.sig
```

JSON report:

```sh
./build/execell package scan --format json package.pkg.tar.zst
```

Rootful mode:

```sh
./build/execell package scan --privileged --yes package.pkg.tar.zst
```

Network is off by default. Mirror URLs require explicit validation:

```sh
./build/execell package scan \
  --network mirror \
  --mirror https://mirror.example.org \
  package.pkg.tar.zst
```

Each successful scan creates a session containing:

- `metadata.json`
- `summary.json`
- `events.jsonl`
- `filesystem.json`
- `processes.json`
- `network.json`
- `risk.json`

Report and cleanup:

```sh
./build/execell package report --format terminal /tmp/execell-package/session-...
./build/execell package cleanup
```

## Security Model

ExeCell is an audit tool, not a proof of complete behavioral coverage. Kernel vulnerabilities,
privileged helpers, unsupported architectures, and host policy restrictions remain outside its
guarantees. Read [`docs/threat-model.md`](docs/threat-model.md) before using it with untrusted
packages.

When Btrfs is unavailable, scanner reports an explicit degraded rootfs mode. Rootless operation
does not claim full pacman semantics when package runtime dependencies are unavailable. Mirror mode
currently remains network-isolated until an allowlisted network namespace is configured.

## Project Status

Prototype with working tracing, sandboxing, package validation, reporting, and security fixtures.
Validate behavior on a dedicated Linux host before enabling rootful scans.

## License

No license has been selected yet.
