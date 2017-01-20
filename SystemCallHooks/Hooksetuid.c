#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/unistd.h>
#include <asm/semaphore.h>
#include <asm/cacheflush.h>

void** SysCallTable;
asmlinkage int (*original_syscall) (const char*, int, int);
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
    SysCallTable = (void*)0xc061e4e0;  //Can be found using: grep "sys_call_table" /boot/System.map-`uname -r` I will
                                       //be adding a function that dynamically/automatically finds this memory location.
    original_call = SysCallTable[__NR_open];
    SetPageAttributes(SysCallTable);
    SysCallTable[__NR_open] = setuidReplacement;
}

void exit_module()
{
   sys_call_table[__NR_open] = original_call;
}
module_init(init_module);
module_exit(exit_module);

MODULE_AUTHOR("Matthew Leon")
MODULE_DESCRIPTION("Kernel Module system call hook");
MODULE_LICENSE("GPL");
