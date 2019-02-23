
#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

/**
 * See man netdevice for info on low-level interface APIs
 *
 * The only information that is required as input is the
 * name of the interface
 */
#include <sys/ioctl.h>
#include <net/if.h>

#define PROT_TCP 6

//#define vmcall_ping(no) __asm__ volatile("movq %0, %%rax\n\t movq %1, %%rdx\n\t vmcall\n\t " :: "rax"(0xBFFFULL), "rdx"(no))

int main(int argc, char **argv)
{
    int in, sock;
    struct sockaddr_in serv_addr, *local_addr;
    struct ifreq ifr;

    sock = socket(AF_INET, SOCK_STREAM, PROT_TCP);

    // Configure the local interface
    ifr.ifr_addr.sa_family = AF_INET;
    memcpy(ifr.ifr_name, "eth0", IFNAMSIZ - 1);

    // set the IP
    local_addr = (struct sockaddr_in *)&ifr.ifr_addr;
    inet_pton(AF_INET, "10.1.10.191", &local_addr->sin_addr);
    if (ioctl(sock, SIOCSIFADDR, &ifr)) {
        printf("Failed to set IF addr: %s\n", strerror(errno));
        exit(errno);
    }

    // set the broadcast addr
    local_addr = (struct sockaddr_in *)&ifr.ifr_broadaddr;
    inet_pton(AF_INET, "10.1.10.255", &local_addr->sin_addr);
    if (ioctl(sock, SIOCSIFBRDADDR, &ifr)) {
        printf("Failed to set brdaddr: %s\n", strerror(errno));
        exit(errno);
    }

    // set the netmask
    local_addr = (struct sockaddr_in *)&ifr.ifr_netmask;
    inet_pton(AF_INET, "255.255.255.0", &local_addr->sin_addr);
    if (ioctl(sock, SIOCSIFNETMASK, &ifr)) {
        printf("Failed to set netmask: %s\n", strerror(errno));
        exit(errno);
    }

    // bring the iface up
    ifr.ifr_flags = IFF_UP;
    if (ioctl(sock, SIOCSIFFLAGS, &ifr)) {
        printf("Failed to set IF flags: %s\n", strerror(errno));
        exit(errno);
    }

    if (sock == -1) {
        //vmcall_ping(2ULL);
        perror("socket failed");
        return 1;
    }
    //vmcall_ping(3ULL);

//    printf("ndvm: socket opened\n");
    //vmcall_ping(4ULL);

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(0xBF00);
//    vmcall_ping(7ULL);

    if (inet_pton(AF_INET, "10.1.10.152", &serv_addr.sin_addr) <= 0) {
//        vmcall_ping(8ULL);
        perror("inet_pton failed");
        return 1;
    }
//    vmcall_ping(9ULL);

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr))) {
        //__asm__ volatile(
        //    "mov $0xF00D, %%rax\n\t"
        //    "mov %0, %%rcx\n\t"
        //    "//vmcall\n\t"
        //    :
        //    : "rcx"((uint64_t)errno)
        //);

        perror("connect failed");
        return 1;
    }

    //vmcall_ping(11ULL);
    //printf("ndvm: connected to 10.1.10.21\n");
    //vmcall_ping(12ULL);

    char *msg = "hello\n";
    //vmcall_ping(13ULL);
    //printf("ndvm: sending msg: %s\n", msg);
    //vmcall_ping(14ULL);

    while (1) {
        send(sock, msg, 7, 0);
        sleep(1);
    }

    //vmcall_ping(15ULL);
    //printf("ndvm: done\n");
    //vmcall_ping(16ULL);
}
