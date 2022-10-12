#include <linux/ftrace.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)) // Linux 5.11 内核中的 ftrace_func_t 结构已更改
#define NEW_KERNEL 1
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0) // Linux 5.7 内核中的 kallsyms_lookup_name 函数不再导出
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};
#endif

#define HOOK(_name, _hook, _orig)	\
{					\
	.name = (_name),		\
	.function = (_hook),		\
	.original = (_orig),		\
}

struct ftrace_hook {
    const char *name;
    void *function;
    void *original;

    unsigned long address;
    struct ftrace_ops ops;
};

int fh_resolve_hook_address(struct ftrace_hook *hook);
#ifdef NEW_KERNEL
void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct ftrace_regs *regs);
#else
void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct pt_regs *regs);
#endif
int fh_install_hook(struct ftrace_hook *hook);
void fh_remove_hook(struct ftrace_hook *hook);
int fh_install_hooks(struct ftrace_hook *hooks, size_t count);
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count);