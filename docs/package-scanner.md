# Package Scanner

`execell package scan` validates local Arch packages before installation.

## Rootless scan

```sh
./build-clang/execell package scan --format terminal --network off package.pkg.tar.zst
```

Rootless mode always fails closed on missing or invalid signatures, rejects unsafe archive paths,
requires Btrfs rootfs isolation, drops capabilities, sets `no_new_privileges`, isolates networking,
and writes session artifacts under `/tmp/execell-package`.

Privileged package scanning is disabled. All package scanning is rootless-only.

## AUR Build

Static `PKGBUILD` analysis:

```sh
./build-clang/execell package build --rootfs /path/to/btrfs/rootfs PKGBUILD
```

Build runs `makepkg` in rootless namespace isolation. Produced artifacts re-enter
package validation. Missing signature rejects artifact validation.

## Baseline

Scan observations are stored in SQLite by default under `/tmp/execell-package`.
Compare stored package versions:

```sh
./build-clang/execell package compare --format json package-name 1.0-1 1.1-1
```

## Reports

Each successful scan writes `metadata.json`, `summary.json`, `events.jsonl`, `filesystem.json`,
`processes.json`, `network.json`, and `risk.json`. Report session with:

```sh
./build-clang/execell package report --format terminal /tmp/execell-package/session-...
```

## Network

`off` is default. `mirror` requires one or more validated `--mirror URL` values. Until an
allowlisted network namespace is available, mirror scans remain isolated and record degraded
network capability instead of exposing host networking.

## Cleanup

```sh
./build-clang/execell package cleanup
```
