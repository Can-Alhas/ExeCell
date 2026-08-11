#include <execell/event/event.hpp>
#include <execell/policy/policy.hpp>
#include <execell/policy/policy_reporter.hpp>
#include <execell/report/summary_reporter.hpp>
#include <execell/sandbox/sandbox.hpp>

#include <cassert>
#include <sys/syscall.h>

int main()
{
    execell::policy::Engine policy{execell::policy::Config{
        .denied_paths = {"/etc"},
        .denied_endpoints = {},
        .denied_syscalls = {},
        .max_processes = 0
    }};
    const execell::event::Event event = execell::event::FileOpened{.path = "/etc/hostname"};
    assert(policy.evaluate(event) == execell::policy::Decision::deny);

    execell::report::Summary summary;
    execell::policy::Reporter policy_reporter{
        execell::policy::Config{.denied_paths = {"/etc"}},
        summary};
    policy_reporter.report(event);
    assert(policy_reporter.denied());

    execell::sandbox::Config invalid{.user_namespace = false, .mount_namespace = true};
    assert(!execell::sandbox::validate(invalid));

    execell::sandbox::Config seccomp_invalid{
        .no_new_privileges = false,
        .seccomp_allowlist = {1}
    };
    assert(!execell::sandbox::validate(seccomp_invalid));

    execell::sandbox::Config seccomp{
        .seccomp_allowlist = {SYS_exit_group}
    };
    const char program[] = "/bin/true";
    char* args[] = {const_cast<char*>(program), nullptr};
    assert(execell::sandbox::run(args[0], args, seccomp) != 0);

    execell::sandbox::Config invalid_root{.read_only_root = true};
    assert(execell::sandbox::validate(invalid_root));
}
