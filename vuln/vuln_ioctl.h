#ifndef VULN_IOCTL_H
#define VULN_IOCTL_H
#include <linux/ioctl.h>

struct pinfo
{
    pid_t pid;
    int reserved1;
};

//#define VULN_GET_VARIABLES _IOR('q', 1, pinfo*)
//#define VULN_CLR_VARIABLES _IO('q', 2)
#define VULN_RAISE_PRIVILEGES _IOW('q', 3, struct pinfo*)
#define VULN_NULL_DEREFERENCE _IO('q', 2)

#endif
