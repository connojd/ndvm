/**
 * Bareflank Hypervisor
 * Copyright (C) 2019 Assured Information Security, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "net.h"
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <vector>
#include <memory>

extern "C" {

const char *hi_addr = NULL;
const char *lo_addr = NULL;

int ndvmfd = -1;
int high_side = 0;

uint64_t _vmcall(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4);

static int open_socket(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        exit(0xBFFF);
    }

    return fd;
}

static void dump_hex(const char *str, size_t len)
{
    for (int i = 0; i < len; i++) {
        printf("%02x", str[i]);
    }
    printf("\n");
}

}

struct channel {
    pthread_t tid;
    int lowfd;
    int highfd;
    char *lowbuf;
    char *highbuf;
    size_t bufsz;
    int low_off;
    int high_off;
    int low_open;
    int high_open;

    channel(int lowfd)
    {
        const int prot = (PROT_READ | PROT_WRITE);
        const int flag = (MAP_PRIVATE | MAP_ANON);

        this->lowfd = lowfd;
        this->bufsz = 4096;

        this->lowbuf = (char *)mmap(NULL, this->bufsz, prot, flag, -1, 0);
        this->highbuf = (char *)mmap(NULL, this->bufsz, prot, flag, -1, 0);
        if (this->lowbuf == MAP_FAILED || this->highbuf == MAP_FAILED) {
            exit(0xCC01);
        }

        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons(PORT);

//        printf("setting INET addr: %s\n", hi_addr);
        if (inet_pton(AF_INET, hi_addr, &sa.sin_addr) < 0) {
            exit(0xCC1U << 16 | errno);
        }

        this->highfd = open_socket();
        if (connect(this->highfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
            printf("connect failed: %s\n", strerror(errno));
            exit(0x66);
        }

        /**
         * Once we get here, we are ready to read from the low side
         */
        low_off = 0;
        low_open = 1;

        high_off = 0;
        high_open = 1;
    }
};

std::vector<std::unique_ptr<struct channel>> chans;


extern "C" {
/**
 * We need to tell linux to pre-fault the mmap'd pages
 * prior to giving them to the hypervisor. Otherwise, the
 * hypervisor will fail to map in the gva properly as the CR3
 * page tables will be invalid. This is done with mlocking here,
 * and mmap()ing later with MAP_POPULATE.
 */

static void init_mem(void)
{
    if (mlockall(MCL_FUTURE) < 0) {
        exit(0xC002);
    }
}

/**
 * Each instance of the NDVM is either on the high-side or
 * the low-side. In either case, the low-side is served and
 * the high-side is connect()ed to. Here we set the high-side
 * address to connect().
 */
static void init_addrs(const char *addr)
{
    if (!strcmp(addr, HI_NIC_ADDR)) {
        hi_addr = HI_END_ADDR;
        high_side = 1;
    } else {
        hi_addr = HI_NIC_ADDR;
        high_side = 0;
    }
}

/**
 * Initialize the NIC with network parameters and bring it up
 * and ready to receive packets.
 */
static void init_nic(char *name, char *ip)
{
    struct ifreq ifr;
    struct sockaddr_in *addr, sa;

    ndvmfd = open_socket();

    // Set interface name
    ifr.ifr_addr.sa_family = AF_INET;
    memcpy(ifr.ifr_name, name, IFNAMSIZ - 1);

    // Set IP address
    addr = (struct sockaddr_in *)&ifr.ifr_addr;
    inet_pton(AF_INET, ip, &addr->sin_addr);
    if (ioctl(ndvmfd, SIOCSIFADDR, &ifr)) {
        exit(0x7703);
    }

    // Set broadcast address
    addr = (struct sockaddr_in *)&ifr.ifr_broadaddr;
    inet_pton(AF_INET, BRD, &addr->sin_addr);
    if (ioctl(ndvmfd, SIOCSIFBRDADDR, &ifr)) {
        exit(0x7704);
    }

    // Set netmask
    addr = (struct sockaddr_in *)&ifr.ifr_netmask;
    inet_pton(AF_INET, MSK, &addr->sin_addr);
    if (ioctl(ndvmfd, SIOCSIFNETMASK, &ifr)) {
        exit(0x7705);
    }

    // Bring it up
    ifr.ifr_flags = IFF_UP;
    if (ioctl(ndvmfd, SIOCSIFFLAGS, &ifr)) {
        exit(0x7706);
    }

    int opt = 1;
    if (setsockopt(ndvmfd, SOL_SOCKET, NIC_OPTS, &opt, sizeof(opt)) < 0) {
        exit(0x7707);
    }

    sa.sin_family = AF_INET;
    sa.sin_port = htons(PORT);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) < 0) {
        exit(0x7708);
    }

    if (bind(ndvmfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        printf("bind failed: %s\n", strerror(errno));
        exit(0x7709);
    }

    if (listen(ndvmfd, 64) < 0) {
        exit(0x770A);
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

static void close_low(struct channel *chn)
{
    munmap(chn->lowbuf, chn->bufsz);
    close(chn->lowfd);
    chn->low_open = 0;
}

static void close_high(struct channel *chn)
{
    munmap(chn->highbuf, chn->bufsz);
    close(chn->highfd);
    chn->high_open = 0;
}

static void dump_chn(struct channel *chn)
{
//    printf("new chn: lowfd: %d, highfd: %d\n", chn->lowfd, chn->highfd);
}

static void *run_channel(void *arg)
{
    sigset_t sigs;
    sigemptyset(&sigs);
    sigaddset(&sigs, SIGPIPE);
    pthread_sigmask(SIG_UNBLOCK, &sigs, NULL);

    auto chn = (struct channel *)(arg);
    dump_chn(chn);

    auto max_fd = (chn->lowfd > chn->highfd) ? chn->lowfd : chn->highfd;

    while (1) {
        fd_set rset;
        fd_set wset;

        FD_ZERO(&rset);
        FD_ZERO(&wset);

        FD_SET(chn->lowfd, &rset);
        FD_SET(chn->lowfd, &wset);
        FD_SET(chn->highfd, &rset);
        FD_SET(chn->highfd, &wset);

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 80000; // timeout of 80ms

        int count = select(max_fd + 1, &rset, &wset, NULL, &tv);
//        int count = select(max_fd + 1, &rset, &wset, NULL, NULL);

        if (count < 0) {
            printf("select failed: %s\n", strerror(errno));
            exit(0xFD << 16 | errno);
        } else if (count == 0) {
            printf("select timedout\n");
            close_low(chn);
            close_high(chn);
            return 0;
        }

        if (FD_ISSET(chn->lowfd, &rset)) {
            int i;
//            do {
                i = recv(chn->lowfd, chn->lowbuf, chn->bufsz, 0);
                if (i > 0) {
                    chn->low_off += i;
//                    printf("setting wset, highfd, lowfd rcvd: ");
//                    dump_hex(chn->lowbuf, i);
                }
                //if (!i) {
                //    close_low(chn);
                //    close_high(chn);
                //    return 0;
                //}
//            } while (i > 0);
        }

        if (FD_ISSET(chn->highfd, &wset)) {
            int i;
//            do {
//                printf("send to highfd");
                i = send(chn->highfd, chn->lowbuf, chn->low_off, 0);
//                printf("send to highfd: %d\n", i);
                if (i > 0) {
                    chn->low_off -= i;
//                    FD_SET(chn->highfd, &rset);
//                    printf("setting rset, highfd\n");
                }
//            } while (i > 0 && chn->low_off > 0);
        }

        if (FD_ISSET(chn->highfd, &rset)) {
            int i;
//            do {
                i = recv(chn->highfd, chn->highbuf, chn->bufsz, 0);
                if (i > 0) {
                    chn->high_off += i;
                }
                if (!i) {
                    close_low(chn);
                    close_high(chn);
                    return 0;
                }
//                    FD_SET(chn->lowfd, &wset);
//                    printf("setting wset, lowfd\n");
//
//                } else if (i == 0) {
////                    printf("highfd HUP\n");
//                }
//            } while (i > 0);
        }

        if (FD_ISSET(chn->lowfd, &wset)) {
            int i;
//            do {
                i = send(chn->lowfd, chn->highbuf, chn->high_off, 0);
                if (i > 0) {
                    chn->high_off -= i;
//                    FD_SET(chn->lowfd, &rset);
//                    printf("setting rset, lowfd\n");
                }
//            } while (i > 0 && chn->high_off > 0);
        }
    }
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        printf("Invalid args\n");
        exit(0xBF01);
    }

    init_mem();
    init_addrs(argv[2]);
    init_nic(argv[1], argv[2]);

    sigset_t sigs;
    sigemptyset(&sigs);
    sigaddset(&sigs, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &sigs, NULL);

    while (1) {
        struct sockaddr_in sa;
        socklen_t len = sizeof(sa);

        auto fd = accept(ndvmfd, (struct sockaddr *)&sa, &len);
        if (fd < 0) {
            exit(0xBF02);
        }

//        dump_sock(ndvmfd, &sa);

        auto t = std::make_unique<struct channel>(fd);
        auto chn = t.get();
        chans.push_back(std::move(t));

        if (pthread_create(&chn->tid, NULL, run_channel, chn) < 0) {
            exit(0xBF03);
        }
    }
}
}
