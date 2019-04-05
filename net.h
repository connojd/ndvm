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

struct filter_desc {
    /* GVA from the fvm */
    uintptr_t fva;

    /* GVA from the ndvm */
    uintptr_t nva;

    /* Number of bytes to filter */
    uintptr_t size;

    uintptr_t pad;
};

static_assert(sizeof(struct filter_desc) == 32);
inline const volatile uint64_t queue_capacity
    = PAGE_SIZE / sizeof(struct filter_desc);

uint64_t _vmcall(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4);

inline void dump_sock(int fd, struct sockaddr_in *sa)
{
    printf("new connection - fd: %d ip: %s port: %d\n",
           fd,
           inet_ntoa(sa->sin_addr),
           ntohs(sa->sin_port));
}
}
#endif

