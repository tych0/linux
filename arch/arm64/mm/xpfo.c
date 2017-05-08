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

#include <asm/tlbflush.h>

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

	pud = pud_offset(pgd, addr);
	if (pud_none(*pud))
		return NULL;

	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd))
		return NULL;

	return pte_offset_kernel(pmd, addr);
}

/* Update a single kernel page table entry */
inline void set_kpte(void *kaddr, struct page *page, pgprot_t prot)
{
	pte_t *pte = lookup_address((unsigned long)kaddr);

	set_pte(pte, pfn_pte(page_to_pfn(page), prot));
}

inline void xpfo_flush_kernel_tlb(struct page *page, int order)
{
	unsigned long kaddr = (unsigned long)page_address(page);
	unsigned long size = PAGE_SIZE;

	flush_tlb_kernel_range(kaddr, kaddr + (1 << order) * size);
}

void xpfo_dma_map_unmap_area(bool map, const void *addr, size_t size,
				    enum dma_data_direction dir)
{
	unsigned long num_pages = XPFO_TEMP_MAP_SIZE(addr, size);
	void *mapping[num_pages];

	xpfo_temp_map(addr, size, mapping, sizeof(void *) * num_pages);

	if (map)
		__dma_map_area(addr, size, dir);
	else
		__dma_unmap_area(addr, size, dir);

	xpfo_temp_unmap(addr, size, mapping, sizeof(void *) * num_pages);
}
