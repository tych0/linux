/*
 * This is for all the tests related to XPFO (eXclusive Page Frame Ownership).
 */

#include "lkdtm.h"

#include <linux/mman.h>
#include <linux/uaccess.h>

/* This is hacky... */
#ifdef CONFIG_ARM64
#define p4d_pfn(p4d)	(0)
#define p4d_large(p4d)	(0)
#define pud_large(pud)	(pud_sect(pud))
#define pmd_large(pmd)	(pmd_sect(pmd))
#endif

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

/* Read from userspace via the kernel's linear map. */
void lkdtm_XPFO_READ_USER(void)
{
	unsigned long user_addr, user_data = 0xdeadbeef;
	phys_addr_t phys_addr;
	void *virt_addr;

	user_addr = vm_mmap(NULL, 0, PAGE_SIZE,
			    PROT_READ | PROT_WRITE | PROT_EXEC,
			    MAP_ANONYMOUS | MAP_PRIVATE, 0);
	if (user_addr >= TASK_SIZE) {
		pr_warn("Failed to allocate user memory\n");
		return;
	}

	if (copy_to_user((void __user *)user_addr, &user_data,
			 sizeof(user_data))) {
		pr_warn("copy_to_user failed\n");
		goto free_user;
	}

	phys_addr = user_virt_to_phys(user_addr);
	if (!phys_addr) {
		pr_warn("Failed to get physical address of user memory\n");
		goto free_user;
	}

	virt_addr = phys_to_virt(phys_addr);
	if (phys_addr != virt_to_phys(virt_addr)) {
		pr_warn("Physical address of user memory seems incorrect\n");
		goto free_user;
	}

	pr_info("Attempting bad read from kernel address %p\n", virt_addr);
	if (*(unsigned long *)virt_addr == user_data)
		pr_info("Huh? Bad read succeeded?!\n");
	else
		pr_info("Huh? Bad read didn't fail but data is incorrect?!\n");

 free_user:
	vm_munmap(user_addr, PAGE_SIZE);
}
