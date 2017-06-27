/*
 * This module tests the XPFO protection for hugepages
 *
 *	Authors:
 *		- Marco Benatto <marco.antonio.780@gmail.com>
 *
 */

#include <linux/module.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/ioctl.h>

#include <asm/uaccess.h>

#define CLASS_NAME "xpfo"
#define DEV_NAME "xpfoht"

#define READ_SHIFT 1
#define XPFO_IOCTL_READ (1 << READ_SHIFT);

#define XPFO_READ _IO('q', 2)


struct xpfo_ht {
	int major;
	struct class *dev_class;
	struct device *dev;
}xpfo_ht;

static int xpfo_ht_dev_open(struct inode *inode, struct file *filp);
static ssize_t xpfo_ht_dev_read(struct file *filep, char __user *buffer,
										size_t len, loff_t *offset);
static ssize_t xpfo_ht_dev_write(struct file *filep, const char __user *buffer,
												size_t len, loff_t *offset);
static int xpfo_ht_dev_release(struct inode *inode, struct file *filp);
static long xpfo_ht_ioctl(struct file *filp, unsigned int op, unsigned long arg);

static struct file_operations fops =
{
	.open = xpfo_ht_dev_open,
	.read = xpfo_ht_dev_read,
	.write = xpfo_ht_dev_write,
	.release = xpfo_ht_dev_release,
	.unlocked_ioctl = xpfo_ht_ioctl
};

static struct xpfo_ht xpfo;

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marco Benatto");
MODULE_VERSION("0.1");


static long xpfo_ht_ioctl(struct file *filp, unsigned int op,
											unsigned long arg) {
	printk(KERN_INFO "test\n");
	pr_info("Will ioctl inode: %lu, op: %d, arg: 0x%lx\n",
						file_inode(filp)->i_ino, op, arg);
	return 10;
}

static int xpfo_ht_dev_open(struct inode *inode, struct file *filp) {
	return 0;
}

static ssize_t xpfo_ht_dev_read(struct file *filep, char __user *buffer,
										 size_t len, loff_t *offset){
	return -EIO;
}

static ssize_t xpfo_ht_dev_write(struct file *filep, const char __user *buffer,
												size_t len, loff_t *offset){
	return -EIO;
}

static int xpfo_ht_dev_release(struct inode *inode, struct file *filp) {
	return 0;
}

static int __init xpfo_ht_init(void) {
	int ret;
	pr_info("Loading XPFO HugePages test module\n");

	ret = 0;
	xpfo.major = register_chrdev(0, DEV_NAME, &fops);

	if (xpfo.major < 0) {
		pr_err("Could not register char device\n");
		return xpfo.major;
	}

	xpfo.dev_class = class_create(THIS_MODULE, CLASS_NAME);

	if (IS_ERR(xpfo.dev_class)) {
		pr_err("Error registering new device class\n");
		ret = PTR_ERR(xpfo.dev_class);
		goto class_error;
	}

	xpfo.dev = device_create(xpfo.dev_class, NULL, MKDEV(xpfo.major, 0), NULL,
																	DEV_NAME);

	if (IS_ERR(xpfo.dev)) {
		ret = PTR_ERR(xpfo.dev);
		goto dev_error;
	}

	pr_info("Successfully created xpfoht device\n");
	return ret;

dev_error:
	class_destroy(xpfo.dev_class);
class_error:
	unregister_chrdev(xpfo.major, DEV_NAME);
	return ret;
}
module_init(xpfo_ht_init);

static void __exit xpfo_ht_exit(void) {
	device_destroy(xpfo.dev_class, MKDEV(xpfo.major,0));
	class_unregister(xpfo.dev_class);
	unregister_chrdev(xpfo.major, DEV_NAME);
	pr_info("XPFO HugePage test device unloaded\n");
}
module_exit(xpfo_ht_exit);
