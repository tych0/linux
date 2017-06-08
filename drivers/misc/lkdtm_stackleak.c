/*
 * This file tests a few aspects of the stackleak compiler plugin:
 *   - the current task stack somewhere below lowest_stack is properly canaried
 *   - small allocas are allowed properly via check_alloca()
 *   - big allocations that exhaust the stack are BUG()s
 *   - a large call chain that exhausts the stack is a BUG()
 *
 * Copyright (C) Docker, Inc. 2017
 *
 * Author: Tycho Andersen <tycho@docker.com>
 */

#include "lkdtm.h"

#include <linux/sched.h>

#define STACKLEAK_POISON -0xbeefL

static bool check_poison(unsigned long *ptr, unsigned long n)
{
	unsigned long i;

	for (i = 1; i < n; i++) {
		if (*(ptr - i) != STACKLEAK_POISON)
			return false;
	}

	return true;
}

static bool check_my_stack(void)
{
	unsigned long *lowest, left, i;

	lowest = &i;
	if ((unsigned long *) current->thread.lowest_stack < lowest)
		lowest = (unsigned long *) current->thread.lowest_stack;

	left = (unsigned long) lowest % THREAD_SIZE;

	/* See note in arch/x86/entry/entry_64.S about the or; the bottom two
	 * qwords are not
	 */
	left -= 2 * sizeof(unsigned long);

	/* let's count the number of canaries, not bytes */
	left /= sizeof(unsigned long);

	for (i = 0; i < left; i++) {
		if (*(lowest - i) != STACKLEAK_POISON)
			continue;

		if (i > 32)
			pr_warn_once("More than 256 bytes not canaried?");

		if (!check_poison(lowest - i, 16))
			continue;

		break;
	}

	if (i == left) {
		pr_warn("didn't find canary?");
		return false;
	}

	if (check_poison((unsigned long *) lowest - i, left - i)) {
		pr_info("current stack poisoned correctly\n");
		return true;
	} else {
		pr_err("current stack not poisoned correctly\n");
		return false;
	}
}

static noinline void do_alloca(unsigned long size)
{
	char buf[size];

	/* so this doesn't get inlined or optimized out */
	snprintf(buf, size, "hello world\n");
}

/* Check the BUG() in check_alloca() */
void lkdtm_STACKLEAK_CHECK_ALLOCA(void)
{
	unsigned long left = (unsigned long) &left % THREAD_SIZE;

	if (!check_my_stack())
		return;

	// try a small allocation to see if it works
	do_alloca(16);
	pr_info("small allocation successful\n");


	pr_info("attempting large alloca of %lu\n", left);
	do_alloca(left);
	pr_warn("alloca succeded?\n");
}
