// SPDX-License-Identifier: GPL-2.0
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/memfd.h>
#include <linux/printk.h>
#include <linux/pagemap.h>
#include <linux/pseudo_fs.h>
#include <linux/set_memory.h>
#include <linux/sched/signal.h>
#include <linux/genalloc.h>
#include <linux/huge_mm.h>

#include <uapi/linux/memfd.h>
#include <uapi/linux/magic.h>

#include <asm/tlbflush.h>

#define SECRETMEM_EXCLUSIVE	0x1
#define SECRETMEM_UNCACHED	0x2

struct secretmem_page_pool {
	struct gen_pool *pool;
	unsigned int nr_pages;
	unsigned int nr_huge;
};

static struct secretmem_page_pool secretmem_page_pool;

struct secretmem_state {
	unsigned int mode;
	unsigned int nr_pages;
};

static int secretmem_pool_refill(gfp_t gfp)
{
	struct gen_pool *pool = secretmem_page_pool.pool;
	unsigned int order = HPAGE_PMD_ORDER, i;
	unsigned int size = (1 << (order + HPAGE_PMD_SHIFT));
	int err;
	struct page *page;
	unsigned long addr;

	/* get a huge page */
	page = alloc_pages(gfp, order);
	if (!page) {
		pr_err("alloc pages failed\n");
		return -ENOMEM;
	}
	/*
	 * TODO: is this really a huge page? there doesn't seem to be an
	 * explicit way to ask for a non-compound huge page, and we need a
	 * non-compound one because we want to split it.
	 */

	printk("alloc'd page at %p\n", page);

	/* split it into 4k pages */
	split_page(page, order);

	addr = (unsigned long)page_address(page);
	err = gen_pool_add(pool, addr, size, NUMA_NO_NODE);
	if (err) {
		pr_err("gen_pool_add failed: %d\n", err);
		__free_pages(page, order);
		return err;
	}

	printk("flushing %lx to %lx\n", addr, addr+size);

	for (i = 0; i < (1 << order); i++) {
		set_direct_map_invalid_noflush(page+i);
	}

	flush_tlb_kernel_range(addr, addr + size);
	return 0;
}

static struct page *secretmem_alloc_page(gfp_t gfp)
{
	struct gen_pool *pool = secretmem_page_pool.pool;
	int err;
	unsigned long addr;
	struct page *page;

	if (gen_pool_avail(pool) < PAGE_SIZE) {
		err = secretmem_pool_refill(gfp);
		if (err)
			return NULL;
	}

	addr = gen_pool_alloc(pool, PAGE_SIZE);
	if (!addr)
		return NULL;

	page = virt_to_page(addr);
	return page;
}

static int secretmem_check_limits(struct vm_fault *vmf)
{
	struct secretmem_state *state = vmf->vma->vm_file->private_data;
	struct inode *inode = file_inode(vmf->vma->vm_file);
	unsigned long limit;

	/*
	 * this check seems broken, i can't write to the mapping at offset zero
	 * because the file is of size zero.
	if (((loff_t)vmf->pgoff << PAGE_SHIFT) >= i_size_read(inode)) {
		printk("i_size_read(): %lld, vmf->pgoff: %lu\n", i_size_read(inode), vmf->pgoff);
		return -EINVAL;
	}
	*/

	limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;
	if (state->nr_pages + 1 >= limit)
		return -EPERM;

	return 0;
}

static vm_fault_t secretmem_fault(struct vm_fault *vmf)
{
	struct secretmem_state *state = vmf->vma->vm_file->private_data;
	struct address_space *mapping = vmf->vma->vm_file->f_mapping;
	pgoff_t offset = vmf->pgoff;
	unsigned long addr;
	struct page *page;
	int ret;

	printk("secretmem fault at %lx\n", vmf->address);

	ret = secretmem_check_limits(vmf);
	if (ret) {
		printk("bad limits %d\n", ret);
		return vmf_error(ret);
	}

	page = find_get_entry(mapping, offset);
	if (!page) {
		printk("didn't find secretmem page\n");
		page = secretmem_alloc_page(vmf->gfp_mask);
		if (!page) {
			printk("failed secretmem_alloc_page\n");
			return vmf_error(-ENOMEM);
		}

		ret = add_to_page_cache_lru(page, mapping, offset, vmf->gfp_mask);
		if (unlikely(ret)) {
			printk("failed adding to page cache %d\n", ret);
			put_page(page);
			return vmf_error(ret);
		}

		/*
		 * theoretically no need to do this here, we should just unmap
		 * everything in the pool and then hand it out already
		 * unmapped. less tlb flushes that way.
		ret = set_direct_map_invalid_noflush(page);
		if (ret) {
			delete_from_page_cache(page);
			return vmf_error(ret);
		}

		addr = (unsigned long)page_address(page);
		flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
		*/

		__SetPageUptodate(page);

		state->nr_pages++;
		ret = VM_FAULT_LOCKED | VM_FAULT_EXCLUSIVE;
	} else {
		printk("secret mapping found\n");
	}

	vmf->page = page;
	printk("secretmem fault returning: %d\n", ret);
	return ret | VM_FAULT_EXCLUSIVE;
}

static const struct vm_operations_struct secretmem_vm_ops = {
	.fault = secretmem_fault,
};

static int secretmem_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct secretmem_state *state = file->private_data;
	unsigned long mode = state->mode;

	if (!mode)
		return -EINVAL;

	switch (mode) {
	case SECRETMEM_UNCACHED:
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
		/* fallthrough */
	case SECRETMEM_EXCLUSIVE:
		vma->vm_ops = &secretmem_vm_ops;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static long secretmem_ioctl(struct file *file, unsigned cmd, unsigned long arg)
{
	struct secretmem_state *state = file->private_data;
	unsigned long mode = state->mode;

	if (mode)
		return -EINVAL;

	switch (cmd) {
	case MFD_SECRET_EXCLUSIVE:
		mode = SECRETMEM_EXCLUSIVE;
		break;
	case MFD_SECRET_UNCACHED:
		mode = SECRETMEM_UNCACHED;
		break;
	default:
		return -EINVAL;
	}

	state->mode = mode;

	return 0;
}

static int secretmem_release(struct inode *inode, struct file *file)
{
	struct secretmem_state *state = file->private_data;

	kfree(state);

	return 0;
}

const struct file_operations secretmem_fops = {
	.release	= secretmem_release,
	.mmap		= secretmem_mmap,
	.unlocked_ioctl = secretmem_ioctl,
	.compat_ioctl	= secretmem_ioctl,
};

static bool secretmem_isolate_page(struct page *page, isolate_mode_t mode)
{
	return false;
}

static int secretmem_migratepage(struct address_space *mapping,
				 struct page *newpage, struct page *page,
				 enum migrate_mode mode)
{
	return -EBUSY;
}

static void secretmem_freepage(struct page *page)
{
	struct gen_pool *pool = secretmem_page_pool.pool;

	gen_pool_free(pool, (unsigned long)page_to_virt(page), PAGE_SIZE);
}

static const struct address_space_operations secretmem_aops = {
	.freepage	= secretmem_freepage,
	.migratepage	= secretmem_migratepage,
	.isolate_page	= secretmem_isolate_page,
};

static struct vfsmount *secretmem_mnt;

struct file *secretmem_file_create(const char *name, unsigned int flags)
{
	struct inode *inode = alloc_anon_inode(secretmem_mnt->mnt_sb);
	struct file *file = ERR_PTR(-ENOMEM);
	struct secretmem_state *state;

	printk("creating secretmem file\n");

	if (IS_ERR(inode))
		return ERR_CAST(inode);

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		goto err_free_inode;

	file = alloc_file_pseudo(inode, secretmem_mnt, "secretmem",
				 O_RDWR, &secretmem_fops);
	if (IS_ERR(file))
		goto err_free_state;

	mapping_set_unevictable(inode->i_mapping);

	inode->i_mapping->private_data = state;
	inode->i_mapping->a_ops = &secretmem_aops;

	/* pretend we are a normal file with zero size */
	inode->i_mode |= S_IFREG;
	inode->i_size = 0;

	file->private_data = state;

	return file;

err_free_state:
	kfree(state);
err_free_inode:
	iput(inode);
	return file;
}

static int secretmem_init_fs_context(struct fs_context *fc)
{
	return init_pseudo(fc, SECRETMEM_MAGIC) ? 0 : -ENOMEM;
}

static struct file_system_type secretmem_fs = {
	.name		= "secretmem",
	.init_fs_context = secretmem_init_fs_context,
	.kill_sb	= kill_anon_super,
};

static int secretmem_init(void)
{
	struct gen_pool *pool;
	int ret = 0;

	pool = gen_pool_create(PAGE_SHIFT, NUMA_NO_NODE);
	if (!pool)
		return -ENOMEM;
	secretmem_page_pool.pool = pool;

	secretmem_mnt = kern_mount(&secretmem_fs);
	if (IS_ERR(secretmem_mnt)) {
		ret = PTR_ERR(secretmem_mnt);
		goto err_destroy_pool;
	}

	return 0;

err_destroy_pool:
	gen_pool_destroy(secretmem_page_pool.pool);
	return ret;
}
fs_initcall(secretmem_init);
