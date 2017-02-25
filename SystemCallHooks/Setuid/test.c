#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/utsname.h>
#include <linux/mm.h>
#include <asm/cacheflush.h>
#include <linux/types.h>



static int __init init_vuln(void)
{
	char vulnBuffer[4];
	struct file* f = 0;
	f = filp_open("/home/mleon/Desktop/KernelModules/SystemCallHooksSetuid/input.txt"
,O_RDONLY,0);
	if (IS_ERR(f) || (f == NULL))
		return 0;
	vfs_read(f,vulnBuffer,26,&f->f_pos);
	filp_close(f,0);
	return 0;
}

static void __exit exit_vuln(void)
{
}

module_init(init_vuln);
module_exit(exit_vuln);
MODULE_LICENSE("GPL");
