#include <stdio.h>
#include <fcntl.h>
#include <string.h>
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

	fd = open("/etc/sudo.conf", O_RDONLY);
	if (fd < 0) {
		perror("open '/etc/sudo.conf' failed:");
		return -1;
	}

	long long q = 0;
	ret = read(fd, &q, sizeof(q)-1);
	close(fd);
	if (ret < 0) {
		error("vuln read failed:");
		return -1;
	}

	printf("success\n");

	return 0;
}
