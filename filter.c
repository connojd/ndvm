#define _GNU_SOURCE

#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>

uint64_t _vmcall(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4);

#define __enum_domain_op 0xBF5C000000000100
#define __enum_domain_op__filter_page 0x144
#define __enum_domain_op__filter_done 0x148

const char *secret = "Earth";
size_t secret_size = 5;
size_t data_size = 4096;

static void filter(char *data)
{
    char *str = (char *)memmem(data, data_size, secret, secret_size);

    while (str) {
        memcpy(str, "Mars ", secret_size);
        str += secret_size;

        if (str > data + data_size - secret_size) {
            break;
        }
        str = (char *)memmem(str, data_size - (str - data), secret, secret_size);
    }
}

int main()
{
    char *data = mmap(NULL, data_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (data == MAP_FAILED) {
        printf("mmap failed: %s\n", strerror(errno));
        exit(1);
    }

    memset(data, 0, data_size);
    printf("data: %x, %x\n", data[0], data[1000]);

    while (1) {
        if (_vmcall(__enum_domain_op, __enum_domain_op__filter_page, (uint64_t)data, 0)) {
            filter(data);
            _vmcall(__enum_domain_op, __enum_domain_op__filter_done, 0, 0);
        }

        usleep(2);
    }
}
