#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/capability.h>

static int drop_root_privileges(uid_t uid)
{
    uid_t suid;

    suid = getuid();
    if (suid != 0) {
        printf("you isn't root\n");
        exit(-1);
    }

    if (setreuid(uid, suid) != 0) {
        perror("drop_root_privileges");
        exit(-1);
    }

    return 0;
}

static int restore_root_privileges()
{
    if (setreuid(0, 0) != 0) {
        perror("restore_root_privileges");
        exit(-1);
    }

    return 0;
}

void drop_cap_setuid(void)
{
    int ret;

    struct __user_cap_header_struct hdr = {};
    struct __user_cap_data_struct data = {};

    memset(&hdr, 0, sizeof(hdr));
    hdr.version = _LINUX_CAPABILITY_VERSION;

    ret = capget(&hdr, &data);
    if (ret < 0) {
        perror("getcap:");
        exit(-1);
    }

    data.effective &= ~CAP_TO_MASK(CAP_SETUID);
    data.permitted &= ~CAP_TO_MASK(CAP_SETUID);


    ret = capset(&hdr, &data);
    if (ret < 0) {
        perror("setcap:");
        exit(-1);
    }
}


int main()
{
    drop_root_privileges(100);
    drop_cap_setuid();

    pid_t pid, pid2;
    int st;
    switch(pid=fork()) {
    case -1:
            perror("fork");
            exit(1);
    case 0:
        restore_root_privileges();
        execl("/bin/bash", "-sh", NULL);
        exit(0);
    default:
            wait(&st);
    }

    return 0;
}
