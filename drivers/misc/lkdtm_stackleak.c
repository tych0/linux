/*
 * This file tests a few aspects of the stackleak compiler plugin:
 *   - the current task stack is properly canaried
 *   - small allocas are allowed properly via check_alloca()
 *   - big allocations that exhaust the stack are BUG()s
 *   - function calls whose stack frames blow the stack are BUG()s
 *
 * Copyright (C) Docker, Inc. 2017
 *
 * Author: Tycho Andersen <tycho@docker.com>
 */

#include "lkdtm.h"

#include <linux/sched.h>
#include <linux/compiler.h>

/* for security_inode_init_security */
#include <linux/security.h>

#ifndef STACKLEAK_POISON
# define STACKLEAK_POISON -0xBEEF
#endif

static noinline bool check_poison(unsigned long *ptr, unsigned long n)
{
	unsigned long i;

	for (i = 0; i < n; i++) {
		if (*(ptr - i) != STACKLEAK_POISON)
			return false;
	}

	return true;
}

static bool check_my_stack(void)
{
	unsigned long *lowest, canaries, left, i;

	lowest = &i;
	left = (unsigned long)lowest % THREAD_SIZE;

	/*
	 * See note in arch/x86/entry/entry_64.S about the or; the bottom two
	 * qwords are not canaried.
	 */
	left -= 2 * sizeof(unsigned long);

	/*
	 * Check each byte, as we don't know the current stack alignment.
	 */
	for (i = 0; i < left; i++) {
		if (*(lowest - i) != STACKLEAK_POISON)
			continue;

		if (!check_poison((void *)lowest - i, 16))
			continue;

		break;
	}

	if (i == left) {
		pr_err("FAIL: didn't find canary?\n");
		return false;
	}

	if (i % sizeof(unsigned long)) {
		pr_err("FAIL: unaligned canary?\n");
		return false;
	}

	/*
	 * How many canaries (not bytes) do we actually need to check?
	 */
	canaries = (left - i) / sizeof(unsigned long *);

	if (check_poison((void *)lowest - i, canaries)) {
		pr_info("stack poisoned correctly, %lu unpoisoned bytes\n", i);
		return true;
	} else {
		pr_err("FAIL: stack not poisoned correctly\n");
		return false;
	}
}

static noinline void do_alloca(unsigned long size, void (*todo)(void))
{
	char buf[size];

	if (todo)
		todo();

	/* so this doesn't get inlined or optimized out */
	snprintf(buf, size, "hello world\n");
}

/* Check the BUG() in check_alloca() */
void lkdtm_STACKLEAK_ALLOCA(void)
{
	unsigned long left = (unsigned long)&left % THREAD_SIZE;

	if (!check_my_stack())
		return;

	/* try a small allocation to see if it works */
	do_alloca(16, NULL);
	pr_info("small allocation successful\n");

	pr_info("attempting large alloca of %lu\n", left);
	do_alloca(left, NULL);
	pr_err("FAIL: large alloca succeded!\n");
}

static void use_some_stack(void) {

	/*
	 * Note: this needs to be a(n exported) function that has track_stack
	 * inserted, i.e. it isn't in the various sections restricted by
	 * stackleak_track_stack_gate.
	 */
	security_inode_init_security(NULL, NULL, NULL, NULL, NULL);
}

/*
 * Note that the way this test fails is kind of ugly; it hits the BUG() in
 * track_stack, but then the BUG() handler blows the stack and hits the stack
 * guard page.
 */
void lkdtm_STACKLEAK_BIG_FRAME(void)
{
	unsigned long left = (unsigned long)&left % THREAD_SIZE;

	if (!check_my_stack())
		return;

	/*
	 * use almost all of the stack up to the padding allowed by track_stack
	 */
	do_alloca(left - THREAD_SIZE / 16 - 1, use_some_stack);
	pr_err("FAIL: stack frame should have blown stack!\n");
}
