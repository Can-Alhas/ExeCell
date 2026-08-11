#pragma once

#include <execell/trace/fd_table.hpp>
#include <execell/trace/syscall_decoder.hpp>

#include <memory>
#include <optional>
#include <unordered_map>

namespace execell::trace {

enum class SyscallPhase { entry, exit, unknown };

class TaskRegistry {
public:
    struct Task {
        pid_t pid{};
        pid_t parent_pid{};
        FdTable fd_table;
        SyscallDecoder decoder;
        SyscallPhase phase{SyscallPhase::entry};

        explicit Task(pid_t value) : pid{value}, decoder{fd_table} {}
        Task(pid_t value, pid_t parent, const FdTable& inherited)
            : pid{value}, parent_pid{parent}, fd_table{inherited}, decoder{fd_table} {}
    };

    Task& insert_root(pid_t pid)
    {
        return *tasks_.emplace(pid, std::make_unique<Task>(pid)).first->second;
    }

    Task& insert_child(pid_t pid, pid_t parent_pid, const FdTable& inherited)
    {
        return *tasks_.emplace(
            pid,
            std::make_unique<Task>(pid, parent_pid, inherited)).first->second;
    }

    [[nodiscard]] Task* find(pid_t pid) noexcept
    {
        const auto it = tasks_.find(pid);
        return it == tasks_.end() ? nullptr : it->second.get();
    }

    void erase(pid_t pid) noexcept { tasks_.erase(pid); }
    [[nodiscard]] bool empty() const noexcept { return tasks_.empty(); }
    [[nodiscard]] std::optional<pid_t> first_pid() const noexcept
    {
        if (tasks_.empty()) {
            return std::nullopt;
        }
        return tasks_.begin()->first;
    }

private:
    std::unordered_map<pid_t, std::unique_ptr<Task>> tasks_;
};

} // namespace execell::trace
