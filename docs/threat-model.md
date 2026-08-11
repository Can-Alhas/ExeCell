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

Sandbox setup failure prevents target execution.

Current limitation: policy reporting does not yet terminate tracees. Seccomp and
namespace restrictions enforce kernel-level sandbox boundaries.
