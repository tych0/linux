/*
 * Copyright (C) Docker, Inc. 2017
 *
 * Author: Tycho Andersen <tycho@docker.com>
 */

#include "gcc-common.h"

__visible int plugin_is_GPL_compatible;

//static GTY(()) tree track_malloc_decl;
//static GTY(()) tree track_free_decl;

static struct plugin_info kerNULL_plugin_info = {
	.version = "0.0.1",
	.help = "kerNULL helps find bugs\n",
};

/*
 * called before GCC exits
 */
static void finish(void *null, void *data)
{
	/*
	fprintf(stderr, "finish\n");
	fflush(stderr);
	*/
}

static unsigned int kerNULL_execute(void)
{
	basic_block bb;

	fprintf(stderr, "analyzing %s\n", IDENTIFIER_POINTER(DECL_NAME(current_function_decl)));

	FOR_EACH_BB_FN(bb, cfun) {
		gimple_stmt_iterator gsi;

		for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
			gimple stmt;
			tree call;
			combined_fn fn;

			stmt = gsi_stmt(gsi);
			if (!is_gimple_call(stmt))
				continue;

			if (is_builtin_fn(call))
				continue;

			call = gimple_call_fndecl(stmt);
			if (call == NULL_TREE)
				continue;

			if (TREE_CODE(call) != CALL_EXPR)
				continue;

			fn = get_call_combined_fn(call);
			if (fn == CFN_LAST);
				continue;

			print_generic_expr(stderr, call, TDF_SLIM);

			print_gimple_stmt(stderr, stmt, 0, 0);

			fprintf(stderr, "TYCHO\n");

			fprintf(stderr, "%p .%s.\n", get_name(call), get_name(call));
			fflush(stderr);
			//gcc_assert(false);
			if (DECL_NAME(call) && !get_name(call)) {
				fprintf(stderr, "call with no name?\n");
				return -1;
			}

			/*
			fprintf(stderr, "call of function %s\n", get_name(call));

			if (!strcmp(get_name(call), "kmalloc") ||
			    !strcmp(get_name(call), "kmalloc_node") ||
			    !strcmp(get_name(call), "kzalloc") ||
			    !strcmp(get_name(call), "kzalloc_node")) {
				tree lhs;
				gcall *track_malloc;
				basic_block bb;
				cgraph_node_ptr node;
				int frequency;

				fprintf(stderr, "call of function %s\n", get_name(call));

				lhs = gimple_get_lhs(stmt);
				if (lhs == NULL_TREE) {
					fprintf(stderr, "alloc without storing return value??\n");
					return -1;
				}

				track_malloc = as_a_gcall(gimple_build_call(track_malloc_decl, 1, lhs));
				gsi_insert_after(&gsi, track_malloc, GSI_NEW_STMT);

				bb = gimple_bb(track_malloc);
				node = cgraph_get_create_node(track_malloc_decl);
				gcc_assert(node);
				frequency = compute_call_stmt_bb_frequency(current_function_decl, bb);
				cgraph_create_edge(cgraph_get_node(current_function_decl), node, track_malloc, bb->count, frequency, bb->loop_length);

				continue;
			}

			if (!strcmp(get_name(call), "kfree")) {
				tree arg;
				gcall *track_free;
				basic_block bb;
				cgraph_node_ptr node;
				int frequency;

				arg = gimple_call_arg(stmt, 1);
				if (arg == NULL_TREE) {
					fprintf(stderr, "kfree with no args?\n");
					return -1;
				}

				fprintf(stderr, "call of function %s\n", get_name(call));

				track_free = as_a_gcall(gimple_build_call(track_free_decl, 1, arg));
				gsi_insert_before(&gsi, track_free, GSI_SAME_STMT);

				bb = gimple_bb(track_free);
				node = cgraph_get_create_node(track_free_decl);
				gcc_assert(node);
				frequency = compute_call_stmt_bb_frequency(current_function_decl, bb);
				cgraph_create_edge(cgraph_get_node(current_function_decl), node, track_free, bb->count, frequency, bb->loop_length);
				continue;
			}

			fprintf(stderr, "done with %s\n", get_name(call));
			*/
		}
	}

	fprintf(stderr, "done with %s\n", IDENTIFIER_POINTER(DECL_NAME(current_function_decl)));
}

static void kerNULL_start_unit(void *gcc, void *unused)
{
	tree fntype;

	// Unset the default signal SIGSEGV handler, in case we do something
	// bad, we want a real stack trace.
	if (signal(SIGSEGV, SIG_DFL) == SIG_ERR)
		perror("signal");

	/*
	// void track_malloc(void *ptr); XXX: FIXME: second void_node_type needs to be a pointer
	fntype = build_function_type_list(void_type_node, void_type_node, NULL_TREE);
	track_malloc_decl = build_fn_decl("track_malloc", fntype);
	DECL_ASSEMBLER_NAME(track_malloc_decl);
	TREE_PUBLIC(track_malloc_decl) = 1;
	TREE_USED(track_malloc_decl) = 1;
	DECL_EXTERNAL(track_malloc_decl) = 1;
	DECL_ARTIFICIAL(track_malloc_decl) = 1;
	DECL_PRESERVE_P(track_malloc_decl) = 1;
	*/
}

#define PASS_NAME kerNULL
#define NO_GATE
#define PROPERTIES_REQUIRED PROP_cfg
#define TODO_FLAGS_START TODO_verify_ssa | TODO_verify_flow | TODO_verify_stmts
#define TODO_FLAGS_FINISH TODO_verify_ssa | TODO_verify_stmts | TODO_dump_func | TODO_update_ssa | TODO_rebuild_cgraph_edges
#include "gcc-generate-gimple-pass.h"

__visible int plugin_init(struct plugin_name_args *plugin_info,
			  struct plugin_gcc_version *version)
{
	const char * const plugin_name = plugin_info->base_name;

	//PASS_INFO(kerNULL, "optimized", 1, PASS_POS_INSERT_BEFORE);
	PASS_INFO(kerNULL, "early_optimizations", 1, PASS_POS_INSERT_BEFORE);

	if (!plugin_default_version_check(version, &gcc_version)) {
		error(G_("incompatible gcc/plugin versions"));
		return 1;
	}

	/*
	register_callback(plugin_info->base_name, PLUGIN_INFO, NULL,
			  &kerNULL_plugin_info);
	*/
	register_callback(plugin_info->base_name, PLUGIN_FINISH, finish, NULL);

	register_callback(plugin_info->base_name, PLUGIN_START_UNIT, &kerNULL_start_unit, NULL);

	register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &kerNULL_pass_info);

	return 0;
}
