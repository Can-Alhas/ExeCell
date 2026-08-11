#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>

int main()
{
    const pid_t child = ::fork();
    if (child == 0) {
        ::_exit(0);
    }
    if (child < 0 || ::waitpid(child, nullptr, 0) < 0) {
        return 1;
    }

    if (::chdir("/tmp") < 0) {
        return 1;
    }
    const int fd = ::open("execell-trace-fixture", O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0) {
        return 1;
    }

    constexpr char text[] = "fixture\n";
    const auto written = ::write(fd, text, sizeof(text) - 1);
    ::close(fd);
    ::unlink("execell-trace-fixture");
    return written == static_cast<ssize_t>(sizeof(text) - 1) ? 0 : 1;
}
