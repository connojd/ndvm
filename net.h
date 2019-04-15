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

#include <atomic>

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
#define __enum_domain_op__sos 0x150
#define __enum_domain_op__headtail 0x151
#define __enum_domain_op__dump_hdr 0x152

uint64_t _vmcall(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4);

inline void sos(uint64_t code)
{
    _vmcall(__enum_domain_op, __enum_domain_op__sos, code, 0);
}

inline void headtail(uint64_t head, uint64_t tail)
{
    _vmcall(__enum_domain_op, __enum_domain_op__headtail, head, tail);
}

inline void dump_hdr(void *hdr)
{
    _vmcall(__enum_domain_op, __enum_domain_op__dump_hdr, (uint64_t)hdr, 0);
}


/**
 * We repurpose the first entry of the queue as the header
 * below to store the head and tail offsets
 */
struct workq_hdr {
    uintptr_t head;
    uintptr_t tail;
    uintptr_t pad[2];
};

struct workq_work {
    /* GVA from the ndvm */
    uintptr_t nva;

    /* Number of bytes to filter */
    uintptr_t size;

    /* GVA from the filter vm */
    uintptr_t fva;

    /* Pad to get a power of 2 */
    uintptr_t pad;
};

/* This can be changed as long as it is a power of two */
static_assert(sizeof(struct workq_work) == 32);

/* NOTE: if this fails, the ptr arithmetic below will be wrong */
static_assert(sizeof(struct workq_work) == sizeof(struct workq_hdr));

/**
 * We go to the next power of two to avoid expensive mod operations. This
 * number depends on the size of struct workq_work and PAGE_SIZE
 */
inline constexpr volatile uint64_t workq_cap =
    PAGE_SIZE / sizeof(struct workq_work); /* max # workq entries + header */

/* Ensure capacity is a reasonable power of two */
static_assert((workq_cap & (workq_cap - 1)) == 0);
static_assert(workq_cap > 2);

inline const volatile uint64_t workq_len = workq_cap >> 1;

/**
 * The workq_* function below assume that the queue's
 * lock is held by the caller
 */
inline bool workq_empty(struct workq_hdr *hdr)
{
    //dump_hdr(hdr);
    return hdr->head == hdr->tail;
}

inline bool workq_full(struct workq_hdr *hdr)
{
    //dump_hdr(hdr);
    return hdr->head == ((hdr->tail + 1) & (workq_len - 1));
}

inline void workq_push(struct workq_hdr *hdr, struct workq_work *in)
{
    hdr->tail = ((hdr->tail + 1) & (workq_len - 1));

    struct workq_work *new_work = (struct workq_work *)(hdr + 1) + hdr->tail;
    memcpy(new_work, in, sizeof(struct workq_work));

    __asm volatile("mfence" : : : "memory");

    //dump_hdr(hdr);
}

inline void workq_pop(struct workq_hdr *hdr,
                      struct workq_work *work)
{
    struct workq_work *cur = (struct workq_work *)(hdr + 1) + hdr->head;

    memcpy(work, cur, sizeof(struct workq_work));
    memset(cur, 0xBF, sizeof(struct workq_work));

    hdr->head = ((hdr->head + 1) & (workq_len - 1));

    __asm volatile("mfence" : : : "memory");
}

inline void acquire_lock(std::atomic<uint64_t> *lock)
{
    uint64_t expected = 0;
    uint64_t desired = 1;

    while (!lock->compare_exchange_weak(expected, desired)) {
        __asm volatile("pause" ::: "memory");
    }

    return;
}

inline void release_lock(std::atomic<uint64_t> *lock)
{
    lock->store(0);
}

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

