
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
    char buf[32];
    struct sockaddr_in serv_addr, *local_addr;
    struct ifreq ifr;

//    vmcall_ping(0ULL);

    // Configure the local interface
    sock = socket(AF_INET, SOCK_STREAM, PROT_TCP);
    ifr.ifr_addr.sa_family = AF_INET;
    memcpy(ifr.ifr_name, "wlp58s0", IFNAMSIZ - 1);
    local_addr = (struct sockaddr_in *)&ifr.ifr_addr;

    // convert to kosher format
    inet_pton(AF_INET, "192.168.0.5", &local_addr->sin_addr);

    // set the address
    if (ioctl(sock, SIOCSIFADDR, &ifr)) {
        printf("Failed to set IF addr: %s\n", strerror(errno));
        exit(errno);
    }

//    vmcall_ping(1ULL);

    if (sock == -1) {
        //vmcall_ping(2ULL);
        perror("socket failed");
        return 1;
    }
    //vmcall_ping(3ULL);

//    printf("ndvm: socket opened\n");
    //vmcall_ping(4ULL);

    memset(buf, 0, sizeof(buf));
    ioctl(sock, SIOCGIFADDR, &ifr);
    strcpy(buf, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
    printf("New IP: %s\n", buf);

//    serv_addr.sin_family = AF_INET;
//    serv_addr.sin_port = htons(0xBF00);
//    vmcall_ping(7ULL);
//
//    if (inet_pton(AF_INET, "10.1.10.21", &serv_addr.sin_addr) <= 0) {
//        vmcall_ping(8ULL);
//        perror("inet_pton failed");
//        return 1;
//    }
//    vmcall_ping(9ULL);
//
//    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr))) {
//        __asm__ volatile(
//            "mov $0xF00D, %%rax\n\t"
//            "mov %0, %%rcx\n\t"
//            "vmcall\n\t"
//            :
//            : "rcx"((uint64_t)errno)
//        );
//
//        //perror("connect failed");
//        return 1;
//    }
//
//    vmcall_ping(11ULL);
//    printf("ndvm: connected to 10.1.10.21\n");
//    vmcall_ping(12ULL);
//
//    char *msg = "hello";
//    vmcall_ping(13ULL);
//    printf("ndvm: sending msg: %s\n", msg);
//    vmcall_ping(14ULL);
//    send(sock, msg, 5, 0);
//    vmcall_ping(15ULL);
//    printf("ndvm: done\n");
//    vmcall_ping(16ULL);
}
