#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    int fd = open("/dev/ttyprintk", O_WRONLY);
    if (fd == -1) {
        exit(1);
    }

    while (1) {
        int rc = write(fd, "hello\n", 6);
        if (!rc) {
            exit(-1);
        } else if (rc != 6) {
            exit(errno);
        }
        sleep(1);
    }
}
