#include <linux/init.h>
#include <linux/jump_label.h>
#include <linux/string.h>
#include <linux/printk.h>
#include <linux/thread_info.h>
#include <asm/current.h>
#include <asm/thread_info.h>

#include <linux/signal.h>

DEFINE_STATIC_KEY_FALSE(bug_on_corruption);
DEFINE_STATIC_KEY_FALSE(kill_on_corruption);

static int __init corruption_param(char *arg)
{
	if (IS_ENABLED(CONFIG_BUG_ON_DATA_CORRUPTION)) {
		if (!strcmp(arg, "bug"))
			pr_warn("corruption=%s supplied, but BUG_ON_DATA_CORRUPTION enabled\n",
				arg);
		static_branch_enable(&bug_on_corruption);
	}

	if (!strcmp(arg, "bug"))
		static_branch_enable(&bug_on_corruption);
	else if (!strcmp(arg, "kill"))
		static_branch_enable(&kill_on_corruption);

	return 0;
}

early_param("corruption", corruption_param);

asmlinkage void return_to_userspace(void)
{
	if (current && test_thread_flag(TIF_KILLME))
		do_exit(SIGKILL);
}
