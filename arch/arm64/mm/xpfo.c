/*
 * Copyright (C) 2017 Hewlett Packard Enterprise Development, L.P.
 * Copyright (C) 2016 Brown University. All rights reserved.
 *
 * Authors:
 *   Juerg Haefliger <juerg.haefliger@hpe.com>
 *   Vasileios P. Kemerlis <vpk@cs.brown.edu>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/xpfo.h>

/*
 * Lookup the page table entry for a virtual address and return a pointer to
 * the entry. Based on x86 tree.
 */
static pte_t *lookup_address(unsigned long addr)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;

	pgd = pgd_offset_k(addr);
	if (pgd_none(*pgd))
		return NULL;

	BUG_ON(pgd_bad(*pgd));

	pud = pud_offset(pgd, addr);
	if (pud_none(*pud))
		return NULL;

	BUG_ON(pud_bad(*pud));

	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd))
		return NULL;

	BUG_ON(pmd_bad(*pmd));

	return pte_offset_kernel(pmd, addr);
}

/* Update a single kernel page table entry */
inline void set_kpte(void *kaddr, struct page *page, pgprot_t prot)
{
	pte_t *pte = lookup_address((unsigned long)kaddr);

	set_pte(pte, pfn_pte(page_to_pfn(page), prot));
}

inline void xpfo_dma_map_unmap_area(bool map, const void *addr, size_t size,
				    int dir)
{
	unsigned long flags;
	void *buf1 = NULL, *buf2 = NULL;
	struct page *page = virt_to_page(addr);

	/* Sanity check */
	BUG_ON(size > PAGE_SIZE);

	local_irq_save(flags);

	/* Map the first page */
	if (xpfo_page_is_unmapped(page))
		buf1 = kmap_atomic(page);

	/* Map the second page if the range crosses a page boundary */
	if (((((unsigned long)addr + size - 1) & PAGE_MASK) !=
	     ((unsigned long)addr & PAGE_MASK)) &&
	    xpfo_page_is_unmapped(page + 1))
		buf2 = kmap_atomic(page + 1);

	if (map)
		__dma_map_area(addr, size, dir);
	else
		__dma_unmap_area(addr, size, dir);

	if (buf1 != NULL)
		kunmap_atomic(buf1);

	if (buf2 != NULL)
		kunmap_atomic(buf2);

	local_irq_restore(flags);
}
