#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/ioctl.h>
#include <linux/kallsyms.h>

#include "vuln_ioctl.h"


static void selinux_flip(void)
{
	static int selinux_enabled_orig, selinux_enforcing_orig;
	int *selinux_enabled_ptr = (int*)kallsyms_lookup_name("selinux_enabled");
	int *selinux_enforcing_ptr = (int*)kallsyms_lookup_name("selinux_enforcing");

	if (!selinux_enabled_ptr || !selinux_enforcing_ptr) {
		return;
	}
	pr_info("selinux_enabled: %d, enforcing: %d\n", *selinux_enabled_ptr, *selinux_enforcing_ptr);

	selinux_enabled_orig = xchg(selinux_enabled_ptr, selinux_enabled_orig);
	selinux_enforcing_orig = xchg(selinux_enforcing_ptr, selinux_enforcing_orig);
}

static void mmap_min_flip(void)
{
	static unsigned long mmap_min_addr_orig;
	unsigned long *mmap_min_addr_ptr = (void*)kallsyms_lookup_name("dac_mmap_min_addr");

	if (!mmap_min_addr_ptr) {
		return;
	}
	pr_info("mmap_min_addr: %lu\n", *mmap_min_addr_ptr);

	mmap_min_addr_orig = xchg(mmap_min_addr_ptr, mmap_min_addr_orig);
}

static void smep_disable(void)
{
	unsigned long val = native_read_cr4();

	clear_bit(20, &val);
	native_write_cr4(val);
}

static void smep_enable(void)
{
	unsigned long val = native_read_cr4();

	set_bit(20, &val);
	native_write_cr4(val);
}

static int null_dereference_call(void)
{
	struct my_ops {
		int (*do_it)(void);
	} *ops = NULL;

	smep_disable();

	ops->do_it();

	smep_enable();

	return 0;
}

static int burn_uid(pid_t pid)
{
	struct task_struct* task;
	for_each_process(task) {
		if (task->pid == pid) {
			struct cred* cred = (struct cred*)task->cred;
			int ret = -EPERM;

			rcu_read_lock();
			if (cred) {
				cred->uid.val = 0; /* get root */
				// cred->suid.val = 0;
				// cred->euid.val = 0;
				// cred->gid.val = 0;
				// cred->sgid.val = 0;
				// cred->egid.val = 0;
				cred->fsuid.val = 0;
				// cred->fsgid.val = 0;
				// cred->user->uid.val = 0;

				pr_info("process: %u rooted\n", pid);
				ret = 0;
			}
			rcu_read_unlock();
			return ret;
		}
	}
	return -ESRCH;
}

static long handle_ioctl(struct file* f, unsigned int cmd, unsigned long arg)
{

	 switch(cmd) {
		case VULN_RAISE_PRIVILEGES: {
			struct pinfo ctx;
			int ret = copy_from_user(&ctx,(struct pinfo*) arg, sizeof(struct pinfo));
			if (ret) {
				printk(KERN_INFO "copy from user failed: %d\n", ret);
				return -EACCES;
			}
			return burn_uid(ctx.pid);
		}
		case VULN_NULL_DEREFERENCE: {
			return null_dereference_call();
		}
		default:
			WARN_ON(0);
			pr_err("invalid cmd: %u\n", cmd);
	}
	return -EINVAL;
}

static int stub_open(struct inode *inode, struct file *f)
{
	return 0;
}

static int stub_close(struct inode *inode, struct file *f)
{
	return 0;
}

static struct file_operations fops =
{
	.owner     = THIS_MODULE,
	.open      = stub_open,
	.release   = stub_close,
	.unlocked_ioctl = handle_ioctl,
};

static struct miscdevice mdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "vuln",
	.fops  = &fops,
	.mode  = 0666,
};

static int __init vuln_init(void)
{
	int ret = misc_register(&mdev);
	if (ret) {
		pr_err("can't register vuln driver: %d\n", ret);
		return ret;
	}
	selinux_flip();
	mmap_min_flip();
	pr_info("Vuln driver loaded\n");

	return 0;
}

static void __exit vuln_exit(void)
{
	mmap_min_flip();
	selinux_flip();
	misc_deregister(&mdev);
	pr_info("Vuln unloaded\n");
}

module_init(vuln_init);
module_exit(vuln_exit);

MODULE_LICENSE("GPL");
