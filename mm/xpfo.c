/*
 * Copyright (C) Docker Inc.
 * Copyright (C) 2017 Hewlett Packard Enterprise Development, L.P.
 * Copyright (C) 2016 Brown University. All rights reserved.
 *
 * Authors:
 *   Tycho Andersen <tycho@docker.com>
 *   Juerg Haefliger <juerg.haefliger@hpe.com>
 *   Vasileios P. Kemerlis <vpk@cs.brown.edu>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

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

DEFINE_STATIC_KEY_FALSE(xpfo_inited);

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
	static_branch_enable(&xpfo_inited);
}

struct page_ext_operations page_xpfo_ops = {
	.size = sizeof(struct xpfo),
	.need = need_xpfo,
	.init = init_xpfo,
};

static inline struct xpfo *lookup_xpfo(struct page *page)
{
	return (void *)lookup_page_ext(page) + page_xpfo_ops.offset;
}

void xpfo_alloc_pages(struct page *page, int order, gfp_t gfp)
{
	int i, flush_tlb = 0;
	struct xpfo *xpfo;
	unsigned long kaddr;

	if (!static_branch_unlikely(&xpfo_inited))
		return;

	for (i = 0; i < (1 << order); i++)  {
		xpfo = lookup_xpfo(page + i);

		BUG_ON(test_bit(XPFO_PAGE_UNMAPPED, &xpfo->flags));

		/* Initialize the map lock and map counter */
		if (unlikely(!xpfo->inited)) {
			spin_lock_init(&xpfo->maplock);
			atomic_set(&xpfo->mapcount, 0);
			xpfo->inited = true;
		}
		BUG_ON(atomic_read(&xpfo->mapcount));

		if ((gfp & GFP_HIGHUSER) == GFP_HIGHUSER) {
			/*
			 * Tag the page as a user page and flush the TLB if it
			 * was previously allocated to the kernel.
			 */
			if (!test_and_set_bit(XPFO_PAGE_USER, &xpfo->flags))
				flush_tlb = 1;
		} else {
			/* Tag the page as a non-user (kernel) page */
			clear_bit(XPFO_PAGE_USER, &xpfo->flags);
		}
	}

	if (flush_tlb) {
		kaddr = (unsigned long)page_address(page);
		flush_tlb_kernel_range(kaddr, kaddr + (1 << order) *
				       PAGE_SIZE);
	}
}

void xpfo_free_pages(struct page *page, int order)
{
	int i;
	struct xpfo *xpfo;

	if (!static_branch_unlikely(&xpfo_inited))
		return;

	for (i = 0; i < (1 << order); i++) {
		xpfo = lookup_xpfo(page + i);

		if (unlikely(!xpfo->inited)) {
			/*
			 * The page was allocated before page_ext was
			 * initialized, so it is a kernel page.
			 */
			continue;
		}

		/*
		 * Map the page back into the kernel if it was previously
		 * allocated to user space.
		 */
		if (test_and_clear_bit(XPFO_PAGE_UNMAPPED, &xpfo->flags)) {
			set_kpte(page_address(page + i), page + i,
				 PAGE_KERNEL);
		}
	}
}

void xpfo_kmap(void *kaddr, struct page *page)
{
	struct xpfo *xpfo;
	unsigned long flags;

	if (!static_branch_unlikely(&xpfo_inited))
		return;

	xpfo = lookup_xpfo(page);

	/*
	 * The page was allocated before page_ext was initialized (which means
	 * it's a kernel page) or it's allocated to the kernel, so nothing to
	 * do.
	 */
	if (unlikely(!xpfo->inited) || !test_bit(XPFO_PAGE_USER, &xpfo->flags))
		return;

	spin_lock_irqsave(&xpfo->maplock, flags);

	/*
	 * The page was previously allocated to user space, so map it back
	 * into the kernel. No TLB flush required.
	 */
	if ((atomic_inc_return(&xpfo->mapcount) == 1) &&
	    test_and_clear_bit(XPFO_PAGE_UNMAPPED, &xpfo->flags))
		set_kpte(kaddr, page, PAGE_KERNEL);

	spin_unlock_irqrestore(&xpfo->maplock, flags);
}
EXPORT_SYMBOL(xpfo_kmap);

void xpfo_kunmap(void *kaddr, struct page *page)
{
	struct xpfo *xpfo;
	unsigned long flags;

	if (!static_branch_unlikely(&xpfo_inited))
		return;

	xpfo = lookup_xpfo(page);

	/*
	 * The page was allocated before page_ext was initialized (which means
	 * it's a kernel page) or it's allocated to the kernel, so nothing to
	 * do.
	 */
	if (unlikely(!xpfo->inited) || !test_bit(XPFO_PAGE_USER, &xpfo->flags))
		return;

	spin_lock_irqsave(&xpfo->maplock, flags);

	/*
	 * The page is to be allocated back to user space, so unmap it from the
	 * kernel, flush the TLB and tag it as a user page.
	 */
	if (atomic_dec_return(&xpfo->mapcount) == 0) {
		BUG_ON(test_bit(XPFO_PAGE_UNMAPPED, &xpfo->flags));
		set_bit(XPFO_PAGE_UNMAPPED, &xpfo->flags);
		set_kpte(kaddr, page, __pgprot(0));
		__flush_tlb_one((unsigned long)kaddr);
	}

	spin_unlock_irqrestore(&xpfo->maplock, flags);
}
EXPORT_SYMBOL(xpfo_kunmap);
