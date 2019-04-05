#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>

#include <mutex>
#include "net.h"

extern "C" {

const char *secret = "Earth";
size_t secret_size = 5;
size_t data_size = 4096;

struct filter_desc *write_queue{0};
struct filter_desc *read_queue{0};

std::mutex *write_mutex{0};
std::mutex *read_mutex{0};

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


int main()
{
    mlockall(MCL_FUTURE);

    const int prot = PROT_READ | PROT_WRITE;
    const int flag = MAP_ANON | MAP_PRIVATE | MAP_POPULATE;

    write_queue = (struct filter_desc *)mmap(NULL, data_size, prot, flag, -1, 0);
    write_mutex = (std::mutex *)mmap(NULL, data_size, prot, flag, -1, 0);
    if (write_queue == MAP_FAILED || write_mutex == MAP_FAILED) {
        exit(0x10);
    }

    read_queue = (struct filter_desc *)mmap(NULL, data_size, prot, flag, -1, 0);
    read_mutex = (std::mutex *)mmap(NULL, data_size, prot, flag, -1, 0);
    if (read_queue == MAP_FAILED || read_mutex == MAP_FAILED) {
        exit(0x20);
    }

    _vmcall(__enum_domain_op,
            __enum_domain_op__set_write_queue,
            (uint64_t)write_queue,
            (uint64_t)write_mutex);

    _vmcall(__enum_domain_op,
            __enum_domain_op__set_read_queue,
            (uint64_t)read_queue,
            (uint64_t)read_mutex);

    while (1) {
    }
}

}
