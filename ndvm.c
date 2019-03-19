
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
#include <sys/time.h>
#include <sys/select.h>

/**
 * See man netdevice for info on low-level net APIs
 */
#include <sys/ioctl.h>
#include <net/if.h>

#define PAGE_SIZE 4096
#define PORT 80

/**
 * IP address map:
 *
 * High-side server has highest address, then decreases
 * by one from high-ndvm -> low-ndvm -> low-client:
 *
 * 192.168.191.103
 * 192.168.191.102
 * 192.168.191.101
 * 192.168.191.100
 */

#define BRD "192.168.191.255"
#define MSK "255.255.255.0"

#define HI_ADDR "192.168.191.102"
#define LO_ADDR "192.168.191.101"

#define __enum_domain_op 0xBF5C000000000100
#define __enum_domain_op__ndvm_share_page 0x143

#define CLIENT_COUNT 2
int client_socks[CLIENT_COUNT];

/* Root listening socket */
int nic_fd;
fd_set read_fds;

uint64_t _vmcall(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4);

/**
 * Initializes the network device and initializes the global nic_fd
 * for later manipulation
 */
static void init_nic(char *name, char *ip)
{
    int addrlen;
    struct ifreq ifr;
    struct sockaddr_in *addr, bind_addr;

    nic_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (nic_fd == -1) {
        exit(0xBF05);
    }

    // Set name
    ifr.ifr_addr.sa_family = AF_INET;
    memcpy(ifr.ifr_name, name, IFNAMSIZ - 1);

    // Set IP address
    addr = (struct sockaddr_in *)&ifr.ifr_addr;
    inet_pton(AF_INET, ip, &addr->sin_addr);
    if (ioctl(nic_fd, SIOCSIFADDR, &ifr)) {
        exit(0xBF02);
    }

    // Set broadcast address
    addr = (struct sockaddr_in *)&ifr.ifr_broadaddr;
    inet_pton(AF_INET, BRD, &addr->sin_addr);
    if (ioctl(nic_fd, SIOCSIFBRDADDR, &ifr)) {
        exit(0xBF03);
    }

    // Set netmask
    addr = (struct sockaddr_in *)&ifr.ifr_netmask;
    inet_pton(AF_INET, MSK, &addr->sin_addr);
    if (ioctl(nic_fd, SIOCSIFNETMASK, &ifr)) {
        exit(0xBF03);
    }

    // Bring it up
    ifr.ifr_flags = IFF_UP;
    if (ioctl(nic_fd, SIOCSIFFLAGS, &ifr)) {
        exit(0xBF04);
    }
}

//static inline void share_page(void *page)
//{
//    _vmcall(__enum_domain_op,
//            __enum_domain_op__ndvm_share_page,
//            (uint64_t)page,
//            0);
//}
//
//static void init_chan(void)
//{
//    shm = aligned_alloc(PAGE_SIZE, PAGE_SIZE);
//    if (!shm) {
//        exit(1);
//    }
//
//    memset(shm, 0, PAGE_SIZE);
//
//    // Hypercall it down. the phys page this maps
//    // to will be what we remap bfexec to
//    share_page(shm);
//}

/**
 * Params:
 *      argv[1]: name of the interface
 *      argv[2]: IPv4 of the interface
 *
 *      Netmask/broadcast addrs are the same for any NDVM
 *      Each NIC has a server and a client
 */

void dump_sock(int fd, struct sockaddr_in *sa)
{
    printf("New connection - fd: %d ip: %s port: %d\n",
           fd,
           inet_ntoa(sa->sin_addr),
           ntohs(sa->sin_port));
}

int main(int argc, char **argv)
{
    struct sockaddr_in nic_sa;
    int nic_sa_len = sizeof(nic_sa);

    if (argc != 3) {
        return 0xBF01;
    }

    init_nic(argv[1], argv[2]);

    memset(&nic_sa, 0, nic_sa_len);
    nic_sa.sin_family = AF_INET;
    nic_sa.sin_port = htons(PORT);
    nic_sa.sin_addr.s_addr = INADDR_ANY;

    if (bind(nic_fd, (struct sockaddr *)&nic_sa, sizeof(nic_sa)) < 0) {
        exit(0xBF02);
    }

    if (listen(nic_fd, CLIENT_COUNT) < 0) {
        exit(0xBF03);
    }

    for (int i = 0; i < CLIENT_COUNT; i++) {
        client_socks[i] = -1;
    }

    // Wait for connections
    while (1) {
        int new_fd = -1;
        int max_fd = nic_fd;

        FD_ZERO(&read_fds);
        FD_SET(nic_fd, &read_fds);

        for (int i = 0; i < CLIENT_COUNT; i++) {
            int fd = client_socks[i];
            if (fd > 0) {
                FD_SET(fd, &read_fds);
                if (fd > max_fd) {
                    max_fd = fd;
                }
            }
        }

        int count = select(max_fd + 1, &read_fds, NULL, NULL, NULL);
        if (count < 0) {
            exit(0xBF04);
        }

        if (FD_ISSET(nic_fd, &read_fds)) {
            new_fd = accept(nic_fd, (struct sockaddr *)&nic_sa, &nic_sa_len);
            if (new_fd < 0) {
                exit(0xBF05);
            }
        }

        dump_sock(new_fd, &nic_sa);
        char *msg = "hello\n";
        if (send(new_fd, msg, strlen(msg), 0) != strlen(msg)) {
            exit(0xBF06);
        }

        for (int i = 0; i < CLIENT_COUNT; i++) {
            if (client_socks[i] == -1) {
                client_socks[i] = new_fd;
                break;
            }
        }
    }
}
