
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

/**
 * See man netdevice for info on low-level net APIs
 */
#include <sys/ioctl.h>
#include <net/if.h>

#define PROT_TCP 6
#define PAGE_SIZE 4096

#define IFNAME "eth0"
#define SERV_IP "10.1.10.22"
#define NDVM_IP "10.1.10.191"
#define NDVM_BRD "10.1.10.255"
#define NDVM_MASK "255.255.255.0"
#define NDVM_PORT 0xBF00

#define __enum_domain_op 0xBF5C000000000100
#define __enum_domain_op__ndvm_share_page 0x143

int fd;
char *shm;
struct ifreq ifr;
struct sockaddr_in serv_addr;
struct sockaddr_in *ndvm_addr;

uint64_t _vmcall(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4);

static void init_ndvm(void)
{
    fd = socket(AF_INET, SOCK_STREAM, PROT_TCP);

    // Set name
    ifr.ifr_addr.sa_family = AF_INET;
    memcpy(ifr.ifr_name, IFNAME, IFNAMSIZ - 1);

    // Set IP address
    ndvm_addr = (struct sockaddr_in *)&ifr.ifr_addr;
    inet_pton(AF_INET, NDVM_IP, &ndvm_addr->sin_addr);
    if (ioctl(fd, SIOCSIFADDR, &ifr)) {
        printf("IP set failed: %s", strerror(errno));
        exit(errno);
    }

    // Set broadcast address
    ndvm_addr = (struct sockaddr_in *)&ifr.ifr_broadaddr;
    inet_pton(AF_INET, NDVM_BRD, &ndvm_addr->sin_addr);
    if (ioctl(fd, SIOCSIFBRDADDR, &ifr)) {
        printf("BRD set failed: %s", strerror(errno));
        exit(errno);
    }

    // Set netmask
    ndvm_addr = (struct sockaddr_in *)&ifr.ifr_netmask;
    inet_pton(AF_INET, NDVM_MASK, &ndvm_addr->sin_addr);
    if (ioctl(fd, SIOCSIFNETMASK, &ifr)) {
        printf("MASK set failed: %s", strerror(errno));
        exit(errno);
    }

    // Bring it up
    ifr.ifr_flags = IFF_UP;
    if (ioctl(fd, SIOCSIFFLAGS, &ifr)) {
        printf("IFF UP failed: %s", strerror(errno));
        exit(errno);
    }
}

static void init_serv(void)
{
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(NDVM_PORT);

    if (inet_pton(AF_INET, SERV_IP, &serv_addr.sin_addr) <= 0) {
        printf("init_serv: inet_pton failed: %s", strerror(errno));
        exit(errno);
    }
}

static inline void share_page(void *page)
{
    _vmcall(__enum_domain_op,
            __enum_domain_op__ndvm_share_page,
            (uint64_t)page,
            0);
}

static void init_chan(void)
{
    shm = aligned_alloc(PAGE_SIZE, PAGE_SIZE);
    if (!shm) {
        exit(1);
    }

    memset(shm, 0, PAGE_SIZE);

    // Hypercall it down. the phys page this maps
    // to will be what we remap bfexec to
    share_page(shm);
}

int main(int argc, char **argv)
{
    int in;
    char data[PAGE_SIZE];

    init_ndvm();
    init_serv();
    init_chan();

    if (connect(fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr))) {
        printf("connect failed: %s", strerror(errno));
        exit(errno);
    }

    do {
        memset(data, 0 , PAGE_SIZE);
        in = read(fd, data, PAGE_SIZE - 1);
        if (in > 0) {
            snprintf(shm + 2, in, "%s", data);
            __asm volatile("mfence");
            *shm = 1; // tell dom0 data is ready
            __asm volatile("mfence");
            while (*shm == 1) { // spin until dom0 starts to read data
                sleep(1);
            }
        }
    } while (in > 0);
}
