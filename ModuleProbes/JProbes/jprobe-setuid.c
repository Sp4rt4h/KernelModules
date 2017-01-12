#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/kprobes.h>
#include <init.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
static struct jprobe setuid_jprobe;
static asmlinkage int kp_setuid(uid_t uid)
{
	printk("process %s [%d] attempted setuid to %d/n",current->comm,current->cred->uid, uid);
	jprobe_return();
	return 0;
}
int init_module(void)
{
	int ret;
	setuid_jprobe.entry = (kprobe_opcode_t *) kp_setuid;
	setuid_jprobe.kp.addr = (kprobe_opcode_t *) kallsyms_lookup_name("sys_setuid");

	if(!setuid_jprobe.kp.addr)
	{
		printk("Unable to look up symbol\n");
		return -1;
	}

	if((ret = register_jprobe(&setuid_jprobe))<0)
	{
		printk("register_jprobe failed, returned %d\n",ret);
		return -1;
	}
	return 0;
}

void exit_module(void)
{
	unregister_jprobe(&setuid_jprobe);
	printk("jprobe unregistered\n");
}
module_init(init_module);
module_exit(exit_module);

MODULE_AUTHOR("Matthew Leon")
MODULE_DESCRIPTION("Kernel Module JProbe");
MODULE_LICENSE("GPL");
