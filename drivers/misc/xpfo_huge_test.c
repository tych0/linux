/*
 * This module tests the XPFO protection for hugepages
 *
 *	Authors:
 *		- Marco Benatto <marco.antonio.780@gmail.com>
 *		- Tycho Andersen <tycho@docker.com>
 *
 */

#include <linux/module.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/ioctl.h>

#include <linux/mman.h>
#include <linux/uaccess.h>

#include <asm/uaccess.h>

#define CLASS_NAME "xpfo"
#define DEV_NAME "xpfoht"

#define READ_SHIFT 1
#define XPFO_IOCTL_READ 6969

// #define XPFO_READ _IO('q', 2)


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

/* we should make this a .o for use in lkdtm and here */
/* Convert a user space virtual address to a physical address.
 * Shamelessly copied from slow_virt_to_phys() and lookup_address() in
 * arch/x86/mm/pageattr.c
 */
static phys_addr_t user_virt_to_phys(unsigned long addr)
{
	phys_addr_t phys_addr;
	unsigned long offset;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pgd = pgd_offset(current->mm, addr);
	if (pgd_none(*pgd))
		return 0;

	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d))
		return 0;

	if (p4d_large(*p4d) || !p4d_present(*p4d)) {
		phys_addr = (unsigned long)p4d_pfn(*p4d) << PAGE_SHIFT;
		offset = addr & ~P4D_MASK;
		goto out;
	}

	pud = pud_offset(p4d, addr);
	if (pud_none(*pud))
		return 0;

	if (pud_large(*pud) || !pud_present(*pud)) {
		phys_addr = (unsigned long)pud_pfn(*pud) << PAGE_SHIFT;
		offset = addr & ~PUD_MASK;
		goto out;
	}

	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd))
		return 0;

	if (pmd_large(*pmd) || !pmd_present(*pmd)) {
		phys_addr = (unsigned long)pmd_pfn(*pmd) << PAGE_SHIFT;
		offset = addr & ~PMD_MASK;
		goto out;
	}

	pte =  pte_offset_kernel(pmd, addr);
	phys_addr = (phys_addr_t)pte_pfn(*pte) << PAGE_SHIFT;
	offset = addr & ~PAGE_MASK;

out:
	return (phys_addr_t)(phys_addr | offset);
}


static long xpfo_ht_ioctl(struct file *filp, unsigned int op,
											unsigned long arg) {
	phys_addr_t phys;
	void *virt_addr;

	/* userspace gives us their mapping for the address, let's map it to
	 * the real page
	 */

	phys = user_virt_to_phys(arg);
	if (!phys)
		return 1;

	virt_addr = phys_to_virt(phys);
	if (phys != virt_to_phys(virt_addr)) {
		pr_warn("Physical address of user memory seems incorrect\n");
		return 2;
	}

	if (*(char *)virt_addr != 0) {
		pr_warn("read succeeded but didn't match?\n");
		return 3;
	}

	return 4;
}

static int xpfo_ht_dev_open(struct inode *inode, struct file *filp) {
	printk("dev opened, ioctl: %d\n", XPFO_IOCTL_READ);
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
