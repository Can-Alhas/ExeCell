#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

int main()
{
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return 1;
    }
    sockaddr_in address{
        .sin_family = AF_INET,
        .sin_port = 0,
        .sin_addr = {.s_addr = htonl(INADDR_LOOPBACK)}
    };
    const bool bound = ::bind(
        fd,
        reinterpret_cast<const sockaddr*>(&address),
        sizeof(address)) == 0;
    const bool listening = bound && ::listen(fd, 1) == 0;
    ::close(fd);
    return listening ? 0 : 1;
}
