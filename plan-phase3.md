# Phase 3: File Descriptor And Path Model

Status: `[x]` complete, `[-]` active, `[ ]` pending.

## Goal

Make descriptor ownership, inherited handles, `dirfd` semantics, and tracee memory
reads explicit and testable.

## Work Items

- [x] Strong `FileDescriptor` integration in `FdTable`.
- [x] Inherited standard descriptor state.
- [x] Unknown descriptor state distinct from regular files.
- [x] `dup`, `dup2`, `dup3` replacement semantics.
- [x] `fcntl(F_DUPFD*)` semantics.
- [x] `close_range` bounded and `UINT_MAX` handling.
- [x] `AT_FDCWD` resolution.
- [x] Directory FD resolution through `/proc/<pid>/fd`.
- [x] Relative path normalization.
- [x] Deleted path handling.
- [x] Typed process-memory read result.
- [x] Truncation metadata.
- [x] Invalid-address metadata.
- [x] Memory read unit tests.
- [x] FD table unit tests.
- [x] Relative-path integration fixture.
- [x] FD reuse integration fixture.
- [x] GCC and Clang build.
- [x] ASan and UBSan test run.

## Exit Criteria

- Unknown inherited descriptors never become fake file paths.
- Relative paths resolve against tracee cwd or directory FD.
- FD reuse cannot retain stale path state.
- Closed and duplicated descriptors preserve correct ownership semantics.
- Memory read failures remain visible to decoder policy.
- All Phase 3 tests pass under GCC and Clang.
