/*
 * This is for all the tests related to XPFO (eXclusive Page Frame Ownership).
 */

#include "lkdtm.h"

#include <linux/cpumask.h>
#include <linux/mman.h>
#include <linux/uaccess.h>
#include <linux/xpfo.h>
#include <linux/kthread.h>

#include <linux/delay.h>
#include <linux/sched/task.h>

#define XPFO_DATA 0xdeadbeef

static unsigned long do_map(unsigned long flags)
{
	unsigned long user_addr, user_data = XPFO_DATA;

	user_addr = vm_mmap(NULL, 0, PAGE_SIZE,
			    PROT_READ | PROT_WRITE | PROT_EXEC,
			    flags, 0);
	if (user_addr >= TASK_SIZE) {
		pr_warn("Failed to allocate user memory\n");
		return 0;
	}

	if (copy_to_user((void __user *)user_addr, &user_data,
			 sizeof(user_data))) {
		pr_warn("copy_to_user failed\n");
		goto free_user;
	}

	return user_addr;

free_user:
	vm_munmap(user_addr, PAGE_SIZE);
	return 0;
}

static unsigned long *user_to_kernel(unsigned long user_addr)
{
	phys_addr_t phys_addr;
	void *virt_addr;

	phys_addr = user_virt_to_phys(user_addr);
	if (!phys_addr) {
		pr_warn("Failed to get physical address of user memory\n");
		return NULL;
	}

	virt_addr = phys_to_virt(phys_addr);
	if (phys_addr != virt_to_phys(virt_addr)) {
		pr_warn("Physical address of user memory seems incorrect\n");
		return NULL;
	}

	return virt_addr;
}

static void read_map(unsigned long *virt_addr)
{
	pr_info("Attempting bad read from kernel address %p\n", virt_addr);
	if (*(unsigned long *)virt_addr == XPFO_DATA)
		pr_err("FAIL: Bad read succeeded?!\n");
	else
		pr_err("FAIL: Bad read didn't fail but data is incorrect?!\n");
}

static void read_user_with_flags(unsigned long flags)
{
	unsigned long user_addr, *kernel;

	user_addr = do_map(flags);
	if (!user_addr) {
		pr_err("FAIL: map failed\n");
		return;
	}

	kernel = user_to_kernel(user_addr);
	if (!kernel) {
		pr_err("FAIL: user to kernel conversion failed\n");
		goto free_user;
	}

	read_map(kernel);

free_user:
	vm_munmap(user_addr, PAGE_SIZE);
}

/* Read from userspace via the kernel's linear map. */
void lkdtm_XPFO_READ_USER(void)
{
	read_user_with_flags(MAP_PRIVATE | MAP_ANONYMOUS);
}

void lkdtm_XPFO_READ_USER_HUGE(void)
{
	read_user_with_flags(MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB);
}

struct smp_arg {
	unsigned long *virt_addr;
	unsigned int cpu;
};

static int smp_reader(void *parg)
{
	struct smp_arg *arg = parg;
	unsigned long *virt_addr;

	if (arg->cpu != smp_processor_id()) {
		pr_err("FAIL: scheduled on wrong CPU?\n");
		return 0;
	}

	virt_addr = smp_cond_load_acquire(&arg->virt_addr, VAL != NULL);
	read_map(virt_addr);

	return 0;
}

#ifdef CONFIG_X86
#define XPFO_SMP_KILLED SIGKILL
#elif CONFIG_ARM64
#define XPFO_SMP_KILLED SIGSEGV
#else
#error unsupported arch
#endif

/* The idea here is to read from the kernel's map on a different thread than
 * did the mapping (and thus the TLB flushing), to make sure that the page
 * faults on other cores too.
 */
void lkdtm_XPFO_SMP(void)
{
	unsigned long user_addr, *virt_addr;
	struct task_struct *thread;
	int ret;
	struct smp_arg arg;

	if (num_online_cpus() < 2) {
		pr_err("not enough to do a multi cpu test\n");
		return;
	}

	arg.virt_addr = NULL;
	arg.cpu = (smp_processor_id() + 1) % num_online_cpus();
	thread = kthread_create(smp_reader, &arg, "lkdtm_xpfo_test");
	if (IS_ERR(thread)) {
		pr_err("couldn't create kthread? %ld\n", PTR_ERR(thread));
		return;
	}

	kthread_bind(thread, arg.cpu);
	get_task_struct(thread);
	wake_up_process(thread);

	user_addr = do_map(MAP_PRIVATE | MAP_ANONYMOUS);
	if (!user_addr)
		goto kill_thread;

	virt_addr = user_to_kernel(user_addr);
	if (!virt_addr) {
		/*
		 * let's store something that will fail, so we can unblock the
		 * thread
		 */
		smp_store_release(&arg.virt_addr, &arg);
		goto free_user;
	}

	smp_store_release(&arg.virt_addr, virt_addr);

	/* there must be a better way to do this. */
	while (1) {
		if (thread->exit_state)
			break;
		msleep_interruptible(100);
	}

free_user:
	if (user_addr)
		vm_munmap(user_addr, PAGE_SIZE);

kill_thread:
	ret = kthread_stop(thread);
	if (ret != XPFO_SMP_KILLED)
		pr_err("FAIL: thread wasn't killed: %d\n", ret);
	put_task_struct(thread);
}
