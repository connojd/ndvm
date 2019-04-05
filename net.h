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

#ifndef _TLP2_NET_H
#define _TLP2_NET_H

extern "C" {

#include <stdint.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/mman.h>
#include <sys/ioctl.h>

/**
 * Address parameters:
 *
 * Filter VM has highest address
 *
 * High-end server has next highest, then decreases
 * by one from high-ndvm -> low-ndvm -> low-end client:
 */

#define HI_END_ADDR "192.168.191.103"
#define HI_NIC_ADDR "192.168.191.102"
#define LO_NIC_ADDR "192.168.191.101"
#define LO_END_ADDR "192.168.191.100"

#define PAGE_SIZE 4096
#define PORT 80
#define BRD "192.168.191.255"
#define MSK "255.255.255.0"

#define NIC_OPTS (SO_REUSEADDR | SO_REUSEPORT)

#define __enum_domain_op 0xBF5C000000000100
#define __enum_domain_op__ndvm_share_page 0x143
#define __enum_domain_op__filter_page 0x144
#define __enum_domain_op__access_ndvm_page 0x147
#define __enum_domain_op__filter_done 0x148

#define __enum_domain_op__map_write_queue 0x149
#define __enum_domain_op__map_read_queue 0x14A
#define __enum_domain_op__set_write_queue 0x14B
#define __enum_domain_op__set_read_queue 0x14C
#define __enum_domain_op__set_write_mutex 0x14D
#define __enum_domain_op__set_read_mutex 0x14E

#define __enum_domain_op__lock_acquired 0x14F

/**
 * We repurpose the first entry of the queue as the header
 * below to store the head and tail offsets
 */
struct filterq_hdr {
    uintptr_t head;
    uintptr_t tail;
    uintptr_t pad[2];
};

struct filterq_work {
    /* GVA from the filter vm */
    uintptr_t fva;

    /* GVA from the ndvm */
    uintptr_t nva;

    /* Number of bytes to filter */
    uintptr_t size;

    /* Pad to get a power of 2 */
    uintptr_t pad;
};

static_assert(sizeof(struct filterq_work) == 32);
static_assert(sizeof(struct filterq_work) == sizeof(struct filterq_hdr));

/* capacity is max work entries + one header */
inline const volatile uint64_t filterq_capacity
    = PAGE_SIZE / sizeof(struct filterq_work);


inline bool filterq_empty(struct filterq_hdr *hdr)
{
    return hdr->head == hdr->tail;
}

inline bool filterq_full(struct filterq_hdr *hdr)
{
    /* Must include the header entry */
    return hdr->head == (hdr->tail + 2) % filterq_capacity;
}

inline void filterq_push(struct filterq_hdr *hdr, struct filterq_work *work)
{

}

inline void push_filterq_work(struct filterq_hdr *hdr,
                              std::mutex *mtx,
                              struct filterq_work *work)
{
    mtx->lock();

    if (filterq_full(hdr)) {
        mtx->unlock();
        return;
    }
    filterq_push(hdr, work);

    mtx->unlock();
}


uint64_t _vmcall(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4);

inline void dump_sock(int fd, struct sockaddr_in *sa)
{
    printf("new connection - fd: %d ip: %s port: %d\n",
           fd,
           inet_ntoa(sa->sin_addr),
           ntohs(sa->sin_port));
}

inline void dump_hex(const char *str, size_t len)
{
    for (int i = 0; i < len; i++) {
        printf("%02x", str[i]);
    }
    printf("\n");
}
}
#endif

