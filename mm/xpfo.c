/*
 * Copyright (C) 2017 Docker, Inc.
 * Copyright (C) 2017 Hewlett Packard Enterprise Development, L.P.
 * Copyright (C) 2016 Brown University. All rights reserved.
 *
 * Authors:
 *   Juerg Haefliger <juerg.haefliger@hpe.com>
 *   Vasileios P. Kemerlis <vpk@cs.brown.edu>
 *   Tycho Andersen <tycho@docker.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/page_ext.h>
#include <linux/xpfo.h>

#include <asm/tlbflush.h>

/* XPFO page state flags */
enum xpfo_flags {
	XPFO_PAGE_USER,		/* Page is allocated to user-space */
	XPFO_PAGE_UNMAPPED,	/* Page is unmapped from the linear map */
};

/* Per-page XPFO house-keeping data */
struct xpfo {
	unsigned long flags;	/* Page state */
	bool inited;		/* Map counter and lock initialized */
	atomic_t mapcount;	/* Counter for balancing map/unmap requests */
	spinlock_t maplock;	/* Lock to serialize map/unmap requests */
};

DEFINE_STATIC_KEY_FALSE(xpfo_initialized);

static bool xpfo_disabled __initdata;

static int __init noxpfo_param(char *str)
{
	xpfo_disabled = true;

	return 0;
}

early_param("noxpfo", noxpfo_param);

static bool __init need_xpfo(void)
{
	if (xpfo_disabled) {
		printk(KERN_INFO "XPFO disabled\n");
		return false;
	}

	return true;
}

static void init_xpfo(void)
{
	printk(KERN_INFO "XPFO enabled\n");
	static_branch_enable(&xpfo_initialized);
}

struct page_ext_operations page_xpfo_ops = {
	.size = sizeof(struct xpfo),
	.need = need_xpfo,
	.init = init_xpfo,
};

bool __init xpfo_enabled(void)
{
	return !xpfo_disabled;
}
EXPORT_SYMBOL(xpfo_enabled);

static inline struct xpfo *lookup_xpfo(struct page *page)
{
	struct page_ext *page_ext = lookup_page_ext(page);

	if (unlikely(!page_ext))
		return NULL;

	return (void *)page_ext + page_xpfo_ops.offset;
}

void xpfo_alloc_pages(struct page *page, int order, gfp_t gfp, bool will_map)
{
	int i, flush_tlb = 0;
	struct xpfo *xpfo;

	if (!static_branch_unlikely(&xpfo_initialized))
		return;

	for (i = 0; i < (1 << order); i++)  {
		xpfo = lookup_xpfo(page + i);
		if (!xpfo)
			continue;

		/* Initialize the map lock and map counter */
		if (unlikely(!xpfo->inited)) {
			spin_lock_init(&xpfo->maplock);
			atomic_set(&xpfo->mapcount, 0);
			xpfo->inited = true;
		}
		WARN(atomic_read(&xpfo->mapcount),
		     "xpfo: already mapped page being allocated\n");

		if ((gfp & GFP_HIGHUSER) == GFP_HIGHUSER) {
			/*
			 * Tag the page as a user page and flush the TLB if it
			 * was previously allocated to the kernel.
			 */
			bool was_kernel = !test_and_set_bit(XPFO_PAGE_USER,
							    &xpfo->flags);

			if (was_kernel || !will_map) {
				set_bit(XPFO_PAGE_UNMAPPED, &xpfo->flags);
				set_kpte(page_address(page + i), page + i,
					 __pgprot(0));
				flush_tlb = 1;
			}
		} else {
			/* Tag the page as a non-user (kernel) page */
			clear_bit(XPFO_PAGE_USER, &xpfo->flags);

			/* If it was previously unmapped, re-map it. */
			if (test_and_clear_bit(XPFO_PAGE_UNMAPPED,
					       &xpfo->flags)) {
				set_kpte(page_address(page + i), page + i,
					 PAGE_KERNEL);
				flush_tlb = 1;
			}
		}
	}

	if (flush_tlb)
		xpfo_flush_kernel_tlb(page, order);
}

void xpfo_free_pages(struct page *page, int order)
{
	/*
	 * Intentional no-op: we leave the pages potentially unmapped by the
	 * kernel until they are needed by it. This saves us a potential TLB
	 * flush when this page is allocated back to userspace again.
	 */
}

void xpfo_kmap(void *kaddr, struct page *page)
{
	struct xpfo *xpfo;

	if (!static_branch_unlikely(&xpfo_initialized))
		return;

	xpfo = lookup_xpfo(page);

	/*
	 * The page was allocated before page_ext was initialized (which means
	 * it's a kernel page) or it's allocated to the kernel, so nothing to
	 * do.
	 */
	if (!xpfo || unlikely(!xpfo->inited) ||
	    !test_bit(XPFO_PAGE_USER, &xpfo->flags))
		return;

	spin_lock(&xpfo->maplock);

	/*
	 * The page was previously allocated to user space, so map it back
	 * into the kernel. No TLB flush required.
	 */
	if ((atomic_inc_return(&xpfo->mapcount) == 1) &&
	    test_and_clear_bit(XPFO_PAGE_UNMAPPED, &xpfo->flags))
		set_kpte(kaddr, page, PAGE_KERNEL);

	spin_unlock(&xpfo->maplock);
}
EXPORT_SYMBOL(xpfo_kmap);

void xpfo_kunmap(void *kaddr, struct page *page)
{
	struct xpfo *xpfo;

	if (!static_branch_unlikely(&xpfo_initialized))
		return;

	xpfo = lookup_xpfo(page);

	/*
	 * The page was allocated before page_ext was initialized (which means
	 * it's a kernel page) or it's allocated to the kernel, so nothing to
	 * do.
	 */
	if (!xpfo || unlikely(!xpfo->inited) ||
	    !test_bit(XPFO_PAGE_USER, &xpfo->flags))
		return;

	spin_lock(&xpfo->maplock);

	/*
	 * The page is to be allocated back to user space, so unmap it from the
	 * kernel, flush the TLB and tag it as a user page.
	 */
	if (atomic_dec_return(&xpfo->mapcount) == 0) {
		WARN(test_bit(XPFO_PAGE_UNMAPPED, &xpfo->flags),
		     "xpfo: unmapping already unmapped page\n");
		set_bit(XPFO_PAGE_UNMAPPED, &xpfo->flags);
		set_kpte(kaddr, page, __pgprot(0));
		xpfo_flush_kernel_tlb(page, 0);
	}

	spin_unlock(&xpfo->maplock);
}
EXPORT_SYMBOL(xpfo_kunmap);

bool xpfo_page_is_unmapped(struct page *page)
{
	struct xpfo *xpfo;

	if (!static_branch_unlikely(&xpfo_initialized))
		return false;

	xpfo = lookup_xpfo(page);
	if (unlikely(!xpfo) && !xpfo->inited)
		return false;

	return test_bit(XPFO_PAGE_UNMAPPED, &xpfo->flags);
}
EXPORT_SYMBOL(xpfo_page_is_unmapped);

void __init_memblock xpfo_phys_alloc(phys_addr_t base, phys_addr_t size)
{
	phys_addr_t cur;
	bool flush_tlb = false;

	if (!static_branch_unlikely(&xpfo_initialized))
		return;

	for (cur = base; cur < base + size; cur += PAGE_SIZE) {
		struct page *page = phys_to_page(cur);
		struct xpfo *xpfo = lookup_xpfo(page);

		if (unlikely(!xpfo) || !xpfo->inited)
			continue;

		/* Only the kernel does physical allocations */
		clear_bit(XPFO_PAGE_UNMAPPED, &xpfo->flags);
		clear_bit(XPFO_PAGE_USER, &xpfo->flags);
		set_kpte(page_address(page), page, PAGE_KERNEL);
		flush_tlb = true;
	}

	if (flush_tlb) {
		unsigned long start = (unsigned long)phys_to_virt(base);
		unsigned long end = (unsigned long)phys_to_virt(base + size);

		/* FIXME: this should really be some form of
		 * xpfo_flush_kernel_tlb() */
		flush_tlb_kernel_range(start, end);
	}
}
EXPORT_SYMBOL(xpfo_phys_alloc);

void xpfo_temp_map(const void *addr, size_t size, void **mapping,
		   size_t mapping_len)
{
	struct page *page = virt_to_page(addr);
	int i, num_pages = mapping_len / sizeof(mapping[0]);

	memset(mapping, 0, mapping_len);

	for (i = 0; i < num_pages; i++) {
		if (page_to_virt(page + i) >= addr + size)
			break;

		if (xpfo_page_is_unmapped(page + i))
			mapping[i] = kmap_atomic(page + i);
	}
}
EXPORT_SYMBOL(xpfo_temp_map);

void xpfo_temp_unmap(const void *addr, size_t size, void **mapping,
		     size_t mapping_len)
{
	int i, num_pages = mapping_len / sizeof(mapping[0]);

	for (i = 0; i < num_pages; i++)
		if (mapping[i])
			kunmap_atomic(mapping[i]);
}
EXPORT_SYMBOL(xpfo_temp_unmap);
