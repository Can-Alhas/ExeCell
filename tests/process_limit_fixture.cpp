#include <sys/wait.h>
#include <unistd.h>

int main()
{
    for (int index = 0; index < 2; ++index) {
        const pid_t child = ::fork();
        if (child == 0) {
            ::_exit(0);
        }
        if (child < 0 || ::waitpid(child, nullptr, 0) < 0) {
            return 1;
        }
    }
    return 0;
}
