/*
 * Copyright (C) 2017 Docker Inc.
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

#include <linux/mm.h>
#include <linux/module.h>

#include <asm/tlbflush.h>

/* Update a single kernel page table entry */
inline void set_kpte(void *kaddr, struct page *page, pgprot_t prot)
{
	pte_t *pte = lookup_address((unsigned long)kaddr, NULL);

	set_pte(pte, pfn_pte(page_to_pfn(page), prot));
}

inline void xpfo_flush_kernel_tlb(struct page *page, int order)
{
	unsigned long kaddr = (unsigned long)page_address(page);
	unsigned long size = PAGE_SIZE;

	flush_tlb_kernel_range(kaddr, kaddr + (1 << order) * size);
}
