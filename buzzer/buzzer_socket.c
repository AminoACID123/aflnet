#define _GNU_SOURCE
#include "buzzer_config.h"
#include "compiler.h"
#include <dlfcn.h>
#include "stdlib.h"
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

static int hci_socket_fd = -1;

void __init connect_hci_socket()
{
    // Create a new server socket with domain: AF_UNIX, type: SOCK_STREAM,
    // protocol: 0
    struct sockaddr_un addr;
    hci_socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);

    // Make sure socket's file descriptor is legit.
    if (hci_socket_fd == -1)
    {
        perror("Error creating hci socket");
        exit(-1);
    }

    printf("Buzzer setup\n");

    // Zero out the address, and set family and path.
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, BZ_HCI_SOCKET_PATH);

    if (connect(hci_socket_fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) == -1)
    {
        perror("Error connecting hci socket");
        exit(-1);
    }

    int rc = ioctl(hci_socket_fd, FIONBIO, (char *)&rc);
    if (rc) {
        perror("Error setting hci socket");
        exit(-1);    
    }

    // char temp[32] = {'\0'};
    // sprintf(temp, "%d", hci_socket_fd);
    // setenv(BTFUZZ_ENV_HCI_SOCKET_FD, temp, 1);
    printf("Buzzer: connect hci socket: %d", hci_socket_fd);
}


int socket(int domain ,int type, int protocol)
{
    int (*original_socket)(int ,int, int);
    original_socket = dlsym(RTLD_NEXT, "socket");

    if (domain == PF_BLUETOOTH)
    {
        printf("Using socket %d", hci_socket_fd);
        return hci_socket_fd;
    }
    else
    {
        return (*original_socket)(domain, type, protocol);
    }
}

int ioctl(int fd, unsigned long request, ...)
{
    return 0;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    return 0;
}