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

/* Convert a user space virtual address to a physical address.
 * Shamelessly copied from slow_virt_to_phys() and lookup_address() in
 * arch/x86/mm/pageattr.c
 */
phys_addr_t user_virt_to_phys(unsigned long addr)
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

	pud = pud_offset(p4d, addr);
	if (pud_none(*pud))
		return 0;

	if (pud_sect(*pud) || !pud_present(*pud)) {
		phys_addr = (unsigned long)pud_pfn(*pud) << PAGE_SHIFT;
		offset = addr & ~PUD_MASK;
		goto out;
	}

	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd))
		return 0;

	if (pmd_sect(*pmd) || !pmd_present(*pmd)) {
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
EXPORT_SYMBOL(user_virt_to_phys);
