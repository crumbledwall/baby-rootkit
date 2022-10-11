#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>


MODULE_LICENSE("Dual MIT/GPL");


static int __init rootkit_init(void)
{

    printk(KERN_ALERT"Rootkit Setted!\n");
    return 0;
}

static void __exit rootkit_exit(void)
{
    printk(KERN_ALERT"Rootkit Exit!\n");
}
module_init(rootkit_init);
module_exit(rootkit_exit);