#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <netinet/in.h>
#include <string_view>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

constexpr std::string_view demo_path{"/tmp/execell-manual-demo.txt"};
constexpr std::string_view risk_marker{ "/tmp/execell-risk-marker.sh" };

bool file_demo()
{
    const int fd = ::open(demo_path.data(), O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0) {
        std::cerr << "file open failed: " << std::strerror(errno) << '\n';
        return false;
    }

    constexpr char text[]{"ExeCell manual fixture\n"};
    const ssize_t written = ::write(fd, text, sizeof(text) - 1U);
    if (written != static_cast<ssize_t>(sizeof(text) - 1U)) {
        std::cerr << "file write failed: " << std::strerror(errno) << '\n';
        ::close(fd);
        return false;
    }
    if (::close(fd) < 0 || ::unlink(demo_path.data()) < 0) {
        std::cerr << "file cleanup failed: " << std::strerror(errno) << '\n';
        return false;
    }
    std::cout << "file demo completed\n";
    return true;
}

bool process_demo()
{
    const pid_t child = ::fork();
    if (child < 0) {
        std::cerr << "fork failed: " << std::strerror(errno) << '\n';
        return false;
    }
    if (child == 0) {
        const char message[] = "child process completed\n";
        (void)::write(STDOUT_FILENO, message, sizeof(message) - 1U);
        ::_exit(0);
    }

    int status{};
    if (::waitpid(child, &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        std::cerr << "child wait failed\n";
        return false;
    }
    std::cout << "process demo completed\n";
    return true;
}

bool network_demo()
{
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        std::cerr << "socket failed: " << std::strerror(errno) << '\n';
        return false;
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = 0;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    const bool bound = ::bind(fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0;
    const bool listening = bound && ::listen(fd, 1) == 0;
    if (::close(fd) < 0 || !listening) {
        std::cerr << "network demo failed: " << std::strerror(errno) << '\n';
        return false;
    }
    std::cout << "network demo completed (loopback listener only)\n";
    return true;
}

bool risk_file_probe(std::string_view path)
{
    const int fd = ::open(path.data(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        std::cout << "risk probe blocked: " << path << " (" << std::strerror(errno) << ")\n";
        return true;
    }
    ::close(fd);
    std::cout << "risk probe opened: " << path << " (no data read)\n";
    return true;
}

bool risk_demo()
{
    bool ok = true;
    for (const std::string_view path : {"/etc/shadow", "/proc/self/environ", "/root/.ssh/id_rsa"}) {
        ok = risk_file_probe(path) && ok;
    }

    const int marker_fd = ::open(risk_marker.data(), O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0700);
    if (marker_fd < 0) {
        std::cerr << "risk marker creation failed: " << std::strerror(errno) << '\n';
        return false;
    }
    constexpr char marker_text[]{"#!/bin/sh\nprintf 'safe marker\\n'\n"};
    const ssize_t written = ::write(marker_fd, marker_text, sizeof(marker_text) - 1U);
    ok = written == static_cast<ssize_t>(sizeof(marker_text) - 1U) && ok;
    ok = ::fchmod(marker_fd, 0700) == 0 && ok;
    ok = ::close(marker_fd) == 0 && ok;
    ok = ::unlink(risk_marker.data()) == 0 && ok;
    std::cout << "risk marker created and removed safely\n";

    const pid_t child = ::fork();
    if (child < 0) {
        std::cerr << "risk child creation failed: " << std::strerror(errno) << '\n';
        return false;
    }
    if (child == 0) {
        ::execl("/bin/true", "true", static_cast<char*>(nullptr));
        ::_exit(127);
    }
    int status{};
    ok = ::waitpid(child, &status, 0) >= 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0 && ok;

    const int network_fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (network_fd >= 0) {
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(9);
        (void)::inet_pton(AF_INET, "192.0.2.1", &address.sin_addr);
        (void)::connect(network_fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address));
        ::close(network_fd);
    }
    std::cout << "risk simulation completed without host modification\n";
    return ok;
}

void usage(const char* program)
{
    std::cout << "Usage: " << program << " [all|file|process|network|risk|fail]\n";
}

} // namespace

int main(int argc, char* argv[])
{
    const std::string_view mode = argc > 1 ? argv[1] : "all";
    if (mode == "--help" || mode == "-h") {
        usage(argv[0]);
        return 0;
    }

    if (mode == "fail") {
        std::cerr << "intentional fixture failure\n";
        return 42;
    }
    if (mode != "all" && mode != "file" && mode != "process" && mode != "network" && mode != "risk") {
        usage(argv[0]);
        return 2;
    }

    bool ok = true;
    if (mode == "all" || mode == "file") ok = file_demo() && ok;
    if (mode == "all" || mode == "process") ok = process_demo() && ok;
    if (mode == "all" || mode == "network") ok = network_demo() && ok;
    if (mode == "risk") ok = risk_demo() && ok;
    return ok ? 0 : 1;
}
