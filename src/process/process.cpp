#include <execell/process/process.hpp>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string_view>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace execell::process {

int run(char *const program, char *const argv[]) {

      const pid_t pid = ::fork();

  if (pid < 0) {
    std::cerr << "execell: fork failed: " << std::strerror(errno) << '\n';
    return EXIT_FAILURE;
  }

  if (pid == 0) {
    ::execvp(program, argv);

    std::cerr << "execell: exec failed: " << std::strerror(errno) << '\n';

    ::_exit(127);
  }

  std::cout << "execell: spawned pid " << pid << '\n';

  int status = 0;

  if (::waitpid(pid, &status, 0) < 0) {
    std::cerr << "execell: waitpid failed: "
              << std::strerror(errno) << '\n';

    return EXIT_FAILURE;
  }

  if (WIFEXITED(status)) {
    const int exit_code = WEXITSTATUS(status);

    std::cout << "[execell] process exited with code " << exit_code << '\n';

    return exit_code;
  }

  if (WIFSIGNALED(status)) {
    const int signal = WTERMSIG(status);

    std::cout << "[execell] process terminated by signal " << signal << '\n';

    return 128 + signal;
  }

  return EXIT_FAILURE;
    
}
    
} // execell::process
