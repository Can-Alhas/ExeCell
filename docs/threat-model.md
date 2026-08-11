# Threat Model

ExeCell observes untrusted Linux programs. Trace output is diagnostic, not proof of
complete behavioral coverage. Kernel bugs, privileged helpers, pre-existing file
descriptors, and unsupported architectures remain outside current guarantees.

Sandbox defaults:

- user namespace enabled;
- mount namespace enabled;
- private mount propagation;
- isolated `tmpfs` at `/tmp`;
- capabilities dropped;
- `PR_SET_NO_NEW_PRIVS` enabled;
- optional CPU and address-space limits;
- optional network namespace.
- optional seccomp allowlist with x86_64 architecture validation;
- policy violations are audit events until enforcement mode is enabled.
- package scanning is rootless-only;
- package scans reject degraded non-Btrfs rootfs sessions.

Sandbox setup failure prevents target execution.

Current limitations: package archive inspection still uses external helper
boundaries pending safe archive adapter work; policy reporting does not yet
terminate tracees. Seccomp and namespace restrictions enforce kernel-level
sandbox boundaries. Valid package signatures establish provenance, not benign
behavior.
