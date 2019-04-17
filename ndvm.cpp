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

#include <list>
#include <vector>
#include <deque>
#include <memory>
#include <mutex>

extern "C" {

/* IP of the high-side server we connect() to*/
const char *high_addr = NULL;

/* Socket for accept()ing new connections from the low-side */
int ndvmfd = -1;

/* Are we the high-side NDVM? */
int high_side = 0;

static int open_socket(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        exit(0xBFFF);
    }

    return fd;
}

static void *mmap_page()
{
    const int prot = (PROT_READ | PROT_WRITE);
    const int flag = (MAP_PRIVATE | MAP_ANON | MAP_POPULATE);

    void *ret = mmap(NULL, PAGE_SIZE, prot, flag, -1, 0);
    if (ret == MAP_FAILED) {
        exit(0x88);
    }

    return ret;
}

struct mmap_work {
    uint8_t *data;
    size_t size;
};

}

/**
 * C++ data and functions
 */

std::vector<std::unique_ptr<struct channel>> chan_ptrs;

struct channel {
    std::deque<struct mmap_work> lowwork;
    std::deque<struct mmap_work> highwork;
    int lowfd;
    int highfd;
    int low_open;
    int high_open;
    int id;

    channel(int lowfd)
    {
        static int id = 0;

        const int prot = (PROT_READ | PROT_WRITE);
        const int flag = (MAP_PRIVATE | MAP_ANON | MAP_POPULATE);

        this->lowfd = lowfd;

        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons(PORT);

        if (inet_pton(AF_INET, high_addr, &sa.sin_addr) < 0) {
            exit(0xCC1U << 16 | errno);
        }

        this->highfd = open_socket();
        if (connect(this->highfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
            printf("connect failed: %s\n", strerror(errno));
            exit(0x66);
        }

        int enable = 1;
        if (setsockopt(this->highfd, SOL_SOCKET, SO_KEEPALIVE, &enable, sizeof(int)) < 0) {
            printf("setsockopt failed: %s\n", strerror(errno));
            exit(0x67);
        }

        /**
         * Once we get here, we are ready to read from the low side
         */
        low_open = 1;
        high_open = 1;
        this->id = ++id;
    }

    bool closed()
    {
        return !this->high_open && !this->low_open;
    }
};

extern "C" {

std::atomic<uint64_t> recv_lock alignas(4096);
struct workq_hdr *recv_hdr{};

std::atomic<uint64_t> send_lock alignas(4096);
struct workq_hdr *send_hdr{};

static void init_workq(void)
{
    recv_hdr = (struct workq_hdr *)mmap_page();
    send_hdr = (struct workq_hdr *)mmap_page();

    recv_lock.store(0);
    send_lock.store(0);

    memset((char *)recv_hdr, 0, PAGE_SIZE);
    memset((char *)send_hdr, 0, PAGE_SIZE);

    //_vmcall(__enum_domain_op,
    //        __enum_domain_op__map_write_queue,
    //        (uint64_t)recv_hdr,
    //        (uint64_t)&recv_lock);

    //_vmcall(__enum_domain_op,
    //        __enum_domain_op__map_read_queue,
    //        (uint64_t)send_hdr,
    //        (uint64_t)&send_lock);
}

/**
 * We need to tell linux to pre-fault the mmap'd pages
 * prior to giving them to the hypervisor. Otherwise, the
 * hypervisor will fail to map in the gva properly as the CR3
 * page tables will be invalid. This is done with mlockall() here,
 * and mmap()ing later with the MAP_POPULATE flag.
 */

static void init_mem(void)
{
    if (mlockall(MCL_FUTURE) < 0) {
        exit(0xC002);
    }
}

/**
 * Each NDVM has a low side and a high side, and each is
 * either on The High Side or The Low Side
 * In either case, the low-side is served and
 * the high-side is connect()ed to. Here we set the high-side
 * address to connect().
 */
static void init_addrs(const char *addr)
{
    if (!strcmp(addr, HI_NIC_ADDR)) {
        high_addr = HI_END_ADDR;
        high_side = 1;
    } else {
        high_addr = HI_NIC_ADDR;
        high_side = 0;
    }
}

/**
 * Initialize the NIC with network parameters and bring it up
 * ready to receive packets.
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

static void close_channel(struct channel *chn)
{
    chn->low_open = 0;
    chn->high_open = 0;

    close(chn->lowfd);
    close(chn->highfd);

//    for (const auto &w : chn->lowwork) {
//        munmap(w.data, PAGE_SIZE);
//    }
//
//    for (const auto& w : chn->highwork) {
//        munmap(w.data, PAGE_SIZE);
//    }
//
//    chn->lowwork.clear();
//    chn->highwork.clear();
}

/**
 * Params:
 *      argv[1]: name of the interface
 *      argv[2]: IPv4 of the interface
 *
 *      Netmask/broadcast addrs are the same for any NDVM
 *      Each NIC has a server and a client
 */

static void sigpipe(int signo)
{
    printf("Received sigpipe\n");
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
    if (high_side) {
        init_workq();
    }

    signal(SIGPIPE, sigpipe);

    while (1) {
        fd_set rset;
        fd_set wset;

        FD_ZERO(&rset);
        FD_ZERO(&wset);

        FD_SET(ndvmfd, &rset);
        int maxfd = ndvmfd;

        for (auto i = 0; i < chan_ptrs.size(); i++) {
            auto chn = chan_ptrs[i].get();
            if (chn->closed()) {
                continue;
            }

            FD_SET(chn->lowfd, &rset);
            FD_SET(chn->lowfd, &wset);
            FD_SET(chn->highfd, &rset);
            FD_SET(chn->highfd, &wset);

            maxfd = (chn->lowfd > maxfd) ? chn->lowfd : maxfd;
            maxfd = (chn->highfd > maxfd) ? chn->highfd : maxfd;
        }

        int count = select(maxfd + 1, &rset, &wset, NULL, NULL);
        if (count < 0) {
            printf("select failed: %s\n", strerror(errno));
            exit(0x10);
        }

        if (FD_ISSET(ndvmfd, &rset)) {
            struct sockaddr_in sa;
            socklen_t len = sizeof(sa);

            auto fd = accept(ndvmfd, (struct sockaddr *)&sa, &len);
            if (fd < 0) {
                exit(0x20);
            }

            chan_ptrs.push_back(std::make_unique<struct channel>(fd));
//            sos(0);
        }

        for (auto i = 0; i < chan_ptrs.size(); i++) {
            auto chn = chan_ptrs[i].get();
            if (chn->closed()) {
                continue;
            }

            char *buf = (char *)MAP_FAILED;
            int n = 0;

            if (FD_ISSET(chn->lowfd, &rset)) {
                buf = (char *)mmap_page();
                n = read(chn->lowfd, buf, PAGE_SIZE);
                if (!n) {
                    close_channel(chn);
                    continue;
                } else if (n < 0) {
                    exit(0x99);
                }
//                sos(1);

                if (FD_ISSET(chn->highfd, &wset)) {
                    int k = write(chn->highfd, buf, n);
                    if (k < 0) {
                        exit(0xA0);
                    }
                    if (k != n) {
                        exit(0xA1);
                    }
                } else {
                    exit(0xA2);
                }
//                sos(2);
                munmap(buf, PAGE_SIZE);
                buf = (char *)MAP_FAILED;
                n = 0;
            }

            if (FD_ISSET(chn->highfd, &rset)) {
                buf = (char *)mmap_page();
                n = read(chn->highfd, buf, PAGE_SIZE);
                if (!n) {
                    close_channel(chn);
                    continue;
                } else if (n < 0) {
                    exit(0xA3);
                }

//                sos(3);
                //if (high_side) {
                //    _vmcall(__enum_domain_op,
                //            __enum_domain_op__ndvm_share_page,
                //            (uintptr_t)buf,
                //            0);

                //    struct workq_work work = {
                //        (uint64_t)buf, (uint64_t)n, (uint64_t)chn->id, 0
                //    };

//              //      sos(4);
                //    acquire_lock(&recv_lock);
                //    workq_push(recv_hdr, &work);
                //    release_lock(&recv_lock);

                //    if (FD_ISSET(chn->lowfd, &wset)) {
//              //      sos(5);
retry:
                //        acquire_lock(&send_lock);
                //        if (workq_empty(send_hdr)) {
                //            release_lock(&send_lock);
//              //              sos(6);
                //            goto retry;
                //        } else {
//              //              sos(7);
                //            struct workq_work work{};
                //            workq_pop(send_hdr, &work);
                //            release_lock(&send_lock);

                //            int k = write(chn->lowfd, buf, n);
                //            if (k < 0) {
                //                exit(0xA4);
                //            }
                //            if (k != n || k != work.size) {
                //                exit(0xA5);
                //            }
                //        }
                //    }
                //} else {
                    if (FD_ISSET(chn->lowfd, &wset)) {
//                        sos(8);
                        int k = write(chn->lowfd, buf, n);
                        if (k < 0) {
                            exit(0xA6);
                        }
                        if (k != n) {
                            exit(0xA7);
                        }
//                        sos(9);
                    }
//                }
//                sos(10);
                munmap(buf, PAGE_SIZE);
            }
        }
    }
}
}
