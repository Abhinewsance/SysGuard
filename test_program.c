#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
    int fd = open("file.txt", O_RDONLY);
    read(fd, buffer, 100);
    close(fd);
    execve("/bin/sh", NULL, NULL);
    return 0;
}
