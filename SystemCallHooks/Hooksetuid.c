#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/unistd.h>
#include <asm/semaphore.h>
#include <asm/cacheflush.h>

void **sys_call_table;

asmlinkage int (*original_call) (const char*, int, int);

asmlinkage int our_sys_open(const char* file, int flags, int mode)
{
   printk("A file was opened\n");
   return original_call(file, flags, mode);
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
    // sys_call_table address in System.map
    sys_call_table = (void*)0xc061e4e0;
    original_call = sys_call_table[__NR_open];

    SetPageAttributes(sys_call_table);
    sys_call_table[__NR_open] = our_sys_open;
}

void exit_module()
{
   // Restore the original call
   sys_call_table[__NR_open] = original_call;
}
module_init(init_module);
module_exit(exit_module);

MODULE_AUTHOR("Matthew Leon")
MODULE_DESCRIPTION("Kernel Module system call hook for setuid");
MODULE_LICENSE("GPL");
