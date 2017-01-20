#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <asm/cacheflush.h>
#include <asm/page.h>
#include <asm/current.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>

#define BOOTPATH  "/boot/System.map-"
unsigned long*  SysCallTable = (unsigned long*)0xTABLE;
asmlinkage int (*original_syscall) (const char*, int, int);

char* GetKernelVersion()
{
	struct file* f;
	char *ver;
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
	printk(KERN_ALERT,"Found the kernel version :D");
	return ver;
}

static int FindMemoryLocationOfSETUID()
{
	char buffer[MAX_LEN];
	char* bufferPointer = buf;
	char* kernelVersion = GetKernelVersion();
	struct file* filePointer;
	mm_segment_t oldfs;
	char* filename = kmalloc(strlen(kernelVersion)+strlen(BOOT_PATH)+1,GFP_KERNEL);
	if(filename == NULL)
		return -1;
	strncpy(filename,BOOT_PATH, strlen(BOOT_PATH);
	strncat(filename,kernelVersion,strlen(kernelVersion));
	filePointer = filp_open(filename,O_RDONLY,0);
	if(IS_ERR(filePointer) || filePointer == NULL)
		return -1;
	int i = 0;
	while(vfs_read(filePointer,bufferPointer+1,&filePointer->f_pos) == 1)
	{
		if(p[1] == 0x10 || i == 0xff)
		{
			i = 0;
			if(strstr(p,"sys_call_table")) != NULL)
			{
				char* sysString = kmalloc(MAX_LEN,GFP_KERNEL);
				if(sys_string == NULL)
				{
					filp_close(filePointer,0);
					set_fs(oldfs);
					kfree(filename);
					return -1;
				}
				memset(sysString, 0, MAX_LEN);
				strncpy(sysString, strsep(&p, " "), MAX_LEN);
				syscall_table = (unsigned long long *) simple_strtoll(sysString, NULL, 16);
				kfree(sysString);
				break;
			}
			memset(buffer, 0x0, MAX_LEN);
			continue;
        	}
        	i++;
	}
	filp_close(filePointer, 0);
	set_fs(oldfs);
	kfree(filename);
	printk(KERN_ALERT,"Found sys_call_table :D");
	return 0;
}

asmlinkage int setuidReplacement(const char* file, int flags, int mode)
{
   printk("setuid has been called\n");
   return original_syscall(file, flags, mode);
}

int SetPageAttributes(long unsigned int _addr)
{
   struct page *pg;
   pgprot_t prot;
   pg = virt_to_page(_addr);
   prot.pgprot = VM_READ | VM_WRITE;
   return change_page_attr(pg, 1, prot);
}

int init_module()
{
    /*SysCallTable = (void*)0xc061e4e0;  //Can be found using: grep "sys_call_table" /boot/System.map-`uname -r` I will
                                       //be adding a function that dynamically/automatically finds this memory location.
    original_call = SysCallTable[__NR_open];
    SetPageAttributes(SysCallTable);
    SysCallTable[__NR_open] = setuidReplacement;*/
	FindMemoryLocationOfSETUID();
}

void exit_module()
{
   //sys_call_table[__NR_open] = original_call;
}
module_init(init_module);
module_exit(exit_module);

MODULE_AUTHOR("Matthew Leon")
MODULE_DESCRIPTION("Kernel Module system call hook");
MODULE_LICENSE("GPL");
