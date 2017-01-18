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

int set_page_rw(long unsigned int _addr)
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

    set_page_rw(sys_call_table);
    sys_call_table[__NR_open] = our_sys_open;
}

void cleanup_module()
{
   // Restore the original call
   sys_call_table[__NR_open] = original_call;
}
