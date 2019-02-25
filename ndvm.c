
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

#define IFNAME "enp2s0"
#define IP_NDVM "10.1.10.191"
#define IP_SERV "10.1.10.22"

/**
 * read_server
 *
 * Read a message from the server
 *
 */
int main(int argc, char **argv)
{
    int in, fd;
    struct sockaddr_in serv_addr, *local_addr;
    struct ifreq ifr;
    char data[PAGE_SIZE];

    fd = socket(AF_INET, SOCK_STREAM, PROT_TCP);

    // Configure the NDVM's interface
    ifr.ifr_addr.sa_family = AF_INET;
    memcpy(ifr.ifr_name, IFNAME, IFNAMSIZ - 1);

    // IP address of NDVM
    local_addr = (struct sockaddr_in *)&ifr.ifr_addr;
    inet_pton(AF_INET, IP_NDVM, &local_addr->sin_addr);
    if (ioctl(fd, SIOCSIFADDR, &ifr)) {
        printf("IP set failed: %s", strerror(errno));
        exit(errno);
    }

    // Broadcast address of NDVM
    local_addr = (struct sockaddr_in *)&ifr.ifr_broadaddr;
    inet_pton(AF_INET, "10.1.10.255", &local_addr->sin_addr);
    if (ioctl(fd, SIOCSIFBRDADDR, &ifr)) {
        printf("BRD set failed: %s", strerror(errno));
        exit(errno);
    }

    // Netmask of NDVM
    local_addr = (struct sockaddr_in *)&ifr.ifr_netmask;
    inet_pton(AF_INET, "255.255.255.0", &local_addr->sin_addr);
    if (ioctl(fd, SIOCSIFNETMASK, &ifr)) {
        printf("MASK set failed: %s", strerror(errno));
        exit(errno);
    }

    // Bring the NIC up
    ifr.ifr_flags = IFF_UP;
    if (ioctl(fd, SIOCSIFFLAGS, &ifr)) {
        printf("IFF UP failed: %s", strerror(errno));
        exit(errno);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(0xBF00);
    if (inet_pton(AF_INET, IP_SERV, &serv_addr.sin_addr) <= 0) {
        printf("IFF UP failed: %s", strerror(errno));
        exit(errno);
    }

    if (connect(fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr))) {
        printf("connect failed: %s", strerror(errno));
        exit(errno);
    }

    do {
        memset(data, 0 , PAGE_SIZE);
        in = read(fd, data, PAGE_SIZE - 1);
        printf("Received msg: %s", data);
        sleep(1);
    } while (in > 0);
}
