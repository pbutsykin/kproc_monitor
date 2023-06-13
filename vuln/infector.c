#include <linux/module.h>

static int __init infector_init(void)
{
	pr_info("test: system infected!\n");

	return 0;
}

static void __exit infector_exit(void)
{}

module_init(infector_init);
module_exit(infector_exit);

MODULE_LICENSE("GPL");
