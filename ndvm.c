
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
#include <signal.h>
#include <time.h>

/**
 * See man netdevice for info on low-level net APIs
 */
#include <sys/ioctl.h>
#include <net/if.h>

#define DATA_SIZE 1024
#define PORT 80
#define BRD "192.168.191.255"
#define MSK "255.255.255.0"

/**
 * IP address map:
 *
 * High-end server has highest address, then decreases
 * by one from high-ndvm -> low-ndvm -> low-end client:
 */

#define HI_END_ADDR "192.168.191.103"
#define HI_NIC_ADDR "192.168.191.102"
#define LO_NIC_ADDR "192.168.191.101"
#define LO_END_ADDR "192.168.191.100"

#define __enum_domain_op 0xBF5C000000000100
#define __enum_domain_op__ndvm_share_page 0x143

#define NIC_OPTS (SO_REUSEADDR | SO_DONTROUTE)

const char *hi_addr = NULL;
const char *lo_addr = NULL;

int nic_fd = -1;

uint64_t _vmcall(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4);

void sig_handler(int signo)
{
    printf("Received SIGPIPE...exiting\n");
    exit(EPIPE);
}

/**
 * Initialize the NIC with network parameters and bring up,
 * ready to receive packets.
 */
static void init_nic(char *name, char *ip)
{

    struct ifreq ifr;
    struct sockaddr_in *addr, sa;

    signal(SIGPIPE, sig_handler);

    nic_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (nic_fd == -1) {
        exit(0xBF02);
    }

    // Set name
    ifr.ifr_addr.sa_family = AF_INET;
    memcpy(ifr.ifr_name, name, IFNAMSIZ - 1);

    // Set IP address
    addr = (struct sockaddr_in *)&ifr.ifr_addr;
    inet_pton(AF_INET, ip, &addr->sin_addr);
    if (ioctl(nic_fd, SIOCSIFADDR, &ifr)) {
        exit(0xBF03);
    }

    // Set broadcast address
    addr = (struct sockaddr_in *)&ifr.ifr_broadaddr;
    inet_pton(AF_INET, BRD, &addr->sin_addr);
    if (ioctl(nic_fd, SIOCSIFBRDADDR, &ifr)) {
        exit(0xBF04);
    }

    // Set netmask
    addr = (struct sockaddr_in *)&ifr.ifr_netmask;
    inet_pton(AF_INET, MSK, &addr->sin_addr);
    if (ioctl(nic_fd, SIOCSIFNETMASK, &ifr)) {
        exit(0xBF05);
    }

    // Bring it up
    ifr.ifr_flags = IFF_UP;
    if (ioctl(nic_fd, SIOCSIFFLAGS, &ifr)) {
        exit(0xBF06);
    }

    int opt = 1;
    if (setsockopt(nic_fd, SOL_SOCKET, NIC_OPTS, &opt, sizeof(opt)) < 0) {
        exit(0xBF07);
    }

    sa.sin_family = AF_INET;
    sa.sin_port = htons(PORT);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) < 0) {
        exit(0xBF08);
    }

    if (bind(nic_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        printf("bind failed: %s\n", strerror(errno));
        exit(0xBF09);
    }

    if (listen(nic_fd, 0) < 0) {
        exit(0xBF0A);
    }
}

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
    printf("new connection - fd: %d ip: %s port: %d\n",
           fd,
           inet_ntoa(sa->sin_addr),
           ntohs(sa->sin_port));
}

void init_addrs(const char *addr)
{
    if (!strcmp(addr, HI_NIC_ADDR)) {
        hi_addr = HI_END_ADDR;
        lo_addr = LO_NIC_ADDR;
    } else {
//        hi_addr = HI_NIC_ADDR;
        hi_addr = HI_END_ADDR;
        lo_addr = LO_END_ADDR;
    }
}

struct channel {
    int lo_fd;
    int hi_fd;
    int data_rdy;
    int size;
    char *data;

};

#define MAX_CHANNELS 16
struct channel chan[MAX_CHANNELS];

int main(int argc, char **argv)
{
    struct sockaddr_in sa, hi_sa;
    int sa_len = sizeof(sa);

    if (argc != 3) {
        printf("Invalid args\n");
        exit(0xBF01);
    }

    init_addrs(argv[2]);
    init_nic(argv[1], argv[2]);

    for (int i = 0; i < MAX_CHANNELS; i++) {
        chan[i].lo_fd = -1;
        chan[i].hi_fd = -1;
        chan[i].size = 0;
        chan[i].data = NULL;
        chan[i].data_rdy = 0;
    }

    while (1) {
        fd_set readset;
        fd_set writeset;

        FD_ZERO(&readset);
        FD_ZERO(&writeset);

        // Add the root fd to the read set. This fd is in charge of
        // accepting new connections from the low side.
        FD_SET(nic_fd, &readset);
        int max_fd = nic_fd;

        for (int i = 0; i < MAX_CHANNELS; i++) {
            if (chan[i].lo_fd != -1) {
                if (chan[i].hi_fd == -1) {
                    exit(78);
                }

                // Add each fd to both read and write sets
                FD_SET(chan[i].lo_fd, &readset);
                FD_SET(chan[i].hi_fd, &readset);
                FD_SET(chan[i].lo_fd, &writeset);
                FD_SET(chan[i].hi_fd, &writeset);

                max_fd = (max_fd < chan[i].lo_fd) ? chan[i].lo_fd : max_fd;
                max_fd = (max_fd < chan[i].hi_fd) ? chan[i].hi_fd : max_fd;
            }
        }

        int count = select(max_fd + 1, &readset, &writeset, NULL, NULL);
        if (count == -1) {
            printf("select failed: %s\n", strerror(errno));
            exit(79);
        }

        // Process a new connection request
        if (FD_ISSET(nic_fd, &readset)) {
            struct sockaddr_in lo_sa, hi_sa;
            int lo_sa_size = sizeof(lo_sa);
            int lo_fd = accept(nic_fd, (struct sockaddr *)&lo_sa, &lo_sa_size);
            if (lo_fd == -1) {
                printf("accept failed: %s\n", strerror(errno));
                exit(80);
            }

            int hi_fd = socket(AF_INET, SOCK_STREAM, 0);
            if (hi_fd == -1) {
                printf("socket failed: %s\n", strerror(errno));
                exit(81);
            }

            memset(&hi_sa, 0, sizeof(hi_sa));
            hi_sa.sin_family = AF_INET;
            hi_sa.sin_port = htons(PORT);
            if (inet_pton(AF_INET, hi_addr, &hi_sa.sin_addr) < 0) {
                exit(82);
            }

            if (connect(hi_fd, (struct sockaddr *)&hi_sa, sizeof(hi_sa)) < 0) {
                printf("connect failed: %s\n", strerror(errno));
                exit(83);
            }

            //int opt = 1;
            //if (setsockopt(hi_fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) < 0) {
            //    printf("setsockopt failed: %s\n", strerror(errno));
            //    exit(0xBF0F);
            //}

            char *data = calloc(DATA_SIZE, 1);
            if (!data) {
                printf("calloc failed\n");
                exit(84);
            }

            int i = 0;
            for (; i < MAX_CHANNELS; i++) {
                if (chan[i].lo_fd == -1) {
                    chan[i].lo_fd = lo_fd;
                    chan[i].hi_fd = hi_fd;
                    chan[i].size = DATA_SIZE;
                    chan[i].data = data;
                    chan[i].data_rdy = 0;
                    break;
                }
            }

            if (i == MAX_CHANNELS) {
                printf("channels maxed out");
                exit(85);
            }
        }

        // Process rw fds
        for (int i = 0; i < MAX_CHANNELS; i++) {
            if (chan[i].lo_fd == -1) {
                continue;
            }

            // Check live fds for r/w availability
            if (FD_ISSET(chan[i].lo_fd, &readset)) {
                if (!chan[i].data_rdy) {
                    int n = read(chan[i].lo_fd, chan[i].data, chan[i].size);
                    if (n < 0) {
                        printf("lo read failed: fd %d, %s\n", chan[i].lo_fd, strerror(errno));
                        exit(86);
                    } else if (n == 0) {
                        close(chan[i].lo_fd);
                        close(chan[i].hi_fd);
                        chan[i].lo_fd = -1;
                        chan[i].hi_fd = -1;
                        chan[i].data_rdy = 0;
                        memset(chan[i].data, 0, chan[i].size);
                    } else {
                        chan[i].data_rdy = 1;
                    }
                } // false here means we are waiting for the write to the high side to complete
            }

            if (FD_ISSET(chan[i].hi_fd, &writeset)) {
                if (chan[i].data_rdy) {
                    int n = write(chan[i].hi_fd, chan[i].data, chan[i].size);
                    if (n < 0) {
                        printf("lo write failed: fd %d, %s\n", chan[i].hi_fd, strerror(errno));
                        exit(87);
                    }
                    chan[i].data_rdy = 0;
                }
            }

            if (FD_ISSET(chan[i].hi_fd, &readset)) {
                if (!chan[i].data_rdy) {
                    int n = read(chan[i].hi_fd, chan[i].data, chan[i].size);
                    if (n < 0) {
                        printf("hi read failed: fd %d, %s\n", chan[i].hi_fd, strerror(errno));
                        exit(88);
                    } else if (n == 0) {
                        close(chan[i].lo_fd);
                        close(chan[i].hi_fd);
                        chan[i].lo_fd = -1;
                        chan[i].hi_fd = -1;
                        chan[i].data_rdy = 0;
                        memset(chan[i].data, 0, chan[i].size);
                    } else {
                        chan[i].data_rdy = 1;
                    }
                }
            }

            if (FD_ISSET(chan[i].lo_fd, &writeset)) {
                if (chan[i].data_rdy) {
                    int n = write(chan[i].lo_fd, chan[i].data, chan[i].size);
                    if (n < 0) {
                        printf("lo write failed: fd %d, %s\n", chan[i].lo_fd, strerror(errno));
                        exit(89);
                    }
                    chan[i].data_rdy = 0;
                }
            }
        }
        usleep(2);
    }
}
