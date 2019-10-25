/* SPDX-License-Identifier: GPL-2.0 */
/*
 * This code tests the madvise(2) flag MADV_SECRET.
 *
 * Authors:
 *   Tycho Andersen <tycho@tycho.ws>
 */
#include "lkdtm.h"
#include <linux/mman.h>

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

void lkdtm_MADV_SECRET(void)
{
	unsigned long user_addr;
	char user_data[] = "meshuggah rocks";
	phys_addr_t phys_addr;
	long ret;
	char *virt_addr;

	user_addr = vm_mmap(NULL, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
			    MAP_SHARED|MAP_ANONYMOUS, 0);
	if (user_addr == TASK_SIZE) {
		pr_err("failed to allocate user memory %lx\n", user_addr);
		return;
	}

	pr_err("mmapped %lx", user_addr);

	/* force the memory to actually be allocated */
	if (copy_to_user((void __user *)user_addr, &user_data,
			 sizeof(user_data))) {
		pr_err("copy_to_user() failed\n");
		return;
	}

	phys_addr = user_virt_to_phys(user_addr);
	if (!phys_addr) {
		pr_err("failed to convert user addr to kernel addr\n");
		return;
	}
	virt_addr = phys_to_virt(phys_addr);
	if (phys_addr != virt_to_phys(virt_addr)) {
		pr_err("physical address seems incorrect");
		return;
	}

	pr_err("phys map location is: %llx\n", phys_addr);
	pr_err("virt location is: %lx\n", (unsigned long)virt_addr);
	/* can we read it normally? */
	if (memcmp(virt_addr, user_data, sizeof(user_data)) == 0) {
		pr_err("unprotected read successful\n");
		return;
	} else {
		pr_err("unprotected read successful and the wrong value\n");
		return;
	}

	/* set MADV_SECRET */
	ret = vm_madvise(user_addr, PAGE_SIZE * 4, MADV_SECRET);
	if (ret < 0) {
		pr_err("madvise failed %ld\n", ret);
		return;
	}

	/* try to read the direct map alias, should explode */
	pr_err("trying to read protected addr\n");
	if (memcmp(virt_addr, user_data, sizeof(user_data)) == 0) {
		pr_err("read successful\n");
		return;
	} else {
		pr_err("read successful and the wrong value\n");
		return;
	}
}
