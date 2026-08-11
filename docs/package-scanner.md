# Package Scanner

`execell package scan` validates local Arch packages before installation.

## Rootless scan

```sh
./build-clang/execell package scan --format terminal --network off package.pkg.tar.zst
```

Rootless mode always fails closed on missing or invalid signatures, rejects unsafe archive paths,
uses a temporary rootfs, drops capabilities, sets `no_new_privileges`, isolates networking, and
writes session artifacts under `/tmp/execell-package`.

## Rootful scan

```sh
./build-clang/execell package scan --privileged --yes package.pkg.tar.zst
```

`--privileged` requires explicit `--yes` in non-interactive use. It is intended only for a
dedicated host. It requires root, `pacman`, and a rootfs containing pacman and its runtime.

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
