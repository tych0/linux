/*
 * Copyright (C) Docker, Inc. 2017
 *
 * Author: Tycho Andersen <tycho@docker.com>
 */

#include "gcc-common.h"

__visible int plugin_is_GPL_compatible;

static struct plugin_info kerNULL_plugin_info = {
	.version = "0.0.1",
	.help = "kerNULL helps find bugs\n",
};

static void finish(void *event_data, void *data)
{
	fprintf(stderr, "finishing: event_data: %p, data: %p\n", event_data, data);
}

static unsigned int kerNULL_execute(void)
{
	basic_block bb;

	fprintf(stderr, "analyzing %s\n", IDENTIFIER_POINTER(DECL_NAME(current_function_decl)));
}

#define PASS_NAME kerNULL
#define NO_GATE
#define PROPERTIES_REQUIRED PROP_cfg
#define TODO_FLAGS_FINISH TODO_dump_func
#include "gcc-generate-gimple-pass.h"

__visible int plugin_init(struct plugin_name_args *plugin_info,
			  struct plugin_gcc_version *version)
{
	PASS_INFO(kerNULL, "optimized", 1, PASS_POS_INSERT_BEFORE);

	if (!plugin_default_version_check(version, &gcc_version)) {
		error(G_("incompatible gcc/plugin versions"));
		return 1;
	}

	register_callback(plugin_info->base_name, PLUGIN_INFO, NULL,
			  &kerNULL_plugin_info);
	register_callback(plugin_info->base_name, PLUGIN_FINISH, finish, NULL);

	register_callback(plugin_info->base_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &kerNULL_pass_info);

	return 0;
}
