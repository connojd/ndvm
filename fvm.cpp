#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>

#include <mutex>
#include <queue>
#include "net.h"

#define PROT (PROT_READ | PROT_WRITE)
#define FLAG (MAP_ANON | MAP_PRIVATE | MAP_POPULATE)

const char *secret = "Earth";
size_t secret_size = 5;
size_t data_size = 4096;

struct workq_hdr *recv_hdr{0};
struct workq_hdr *send_hdr{0};

//TODO: change to atomic_lock
std::atomic<uint64_t> *recv_lock;
std::atomic<uint64_t> *send_lock;

std::queue<struct workq_work> recvq;
std::queue<struct workq_work> sendq;

extern "C" {

static void filter_body(char *data)
{
    char *start = (char *)memmem(data, data_size, "<body>", 6);
    if (!start) {
        return;
    }

    char *end = (char *)memmem((start + 6),
                               data_size - (size_t)((start - data) + 6),
                               "</body>",
                               7);
    if (!end) {
        return;
    }

    char *body = start + 6;
    for (int i = 0; body + i < end; i++) {
        if (body[i] >= 'a' && body[i] <= 'z') {
            body[i] -= 32;
        } else if (body[i] >= 'A' && body[i] <= 'Z') {
            body[i] += 32;
        }
    }
}

void filter(const struct workq_work &work)
{
    // Get a virtual address
    char *fva = (char *)mmap(NULL, data_size, PROT, FLAG, -1, 0);
    if (fva == MAP_FAILED) {
        exit(errno);
    }

    // Map in the NDVM's page
    _vmcall(__enum_domain_op,
            __enum_domain_op__filter_page,
            (uint64_t)fva,
            work.nva);

    // Filter bad words
    filter_body(fva);

    // Unmap virt
    munmap(fva, data_size);
}

int main()
{
    mlockall(MCL_FUTURE);

    const int prot = PROT_READ | PROT_WRITE;
    const int flag = MAP_ANON | MAP_PRIVATE | MAP_POPULATE;

    recv_hdr = (struct workq_hdr *)mmap(NULL, data_size, prot, flag, -1, 0);
    recv_lock = (std::atomic<uint64_t> *)mmap(NULL, data_size, prot, flag, -1, 0);
    if (recv_hdr == MAP_FAILED || recv_lock == MAP_FAILED) {
        exit(0x10);
    }

    send_hdr = (struct workq_hdr *)mmap(NULL, data_size, prot, flag, -1, 0);
    send_lock = (std::atomic<uint64_t> *)mmap(NULL, data_size, prot, flag, -1, 0);
    if (send_hdr == MAP_FAILED || send_lock == MAP_FAILED) {
        exit(0x20);
    }

    _vmcall(__enum_domain_op,
            __enum_domain_op__set_write_queue,
            (uint64_t)recv_hdr,
            (uint64_t)recv_lock);

    _vmcall(__enum_domain_op,
            __enum_domain_op__set_read_queue,
            (uint64_t)send_hdr,
            (uint64_t)send_lock);

    headtail(recv_hdr->head, recv_hdr->tail);

    while (1) {
        acquire_lock(recv_lock);
        //sos(0xFF);
        if (!workq_empty(recv_hdr)) {
    //        sos(0xFE);
            struct workq_work work;
            workq_pop(recv_hdr, &work);
    //        headtail(recv_hdr->head, recv_hdr->tail);
            recvq.push(work);
        } else {
   //         headtail(recv_hdr->head, recv_hdr->tail);
        }
        release_lock(recv_lock);

        while (!recvq.empty()) {
    //        sos(0xFD);
            filter(recvq.front());
            sendq.push(recvq.front());
            recvq.pop();
        }

        acquire_lock(send_lock);
        while (!sendq.empty()) {
   //         sos(0xFB);
            if (!workq_full(send_hdr)) {
   //             sos(0xFA);
                auto work = sendq.front();
                workq_push(send_hdr, &work);
                sendq.pop();
    //            headtail(recv_hdr->head, recv_hdr->tail);
            }
        }
        release_lock(send_lock);
    }
}
}
