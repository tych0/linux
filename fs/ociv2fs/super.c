#include <linux/slab.h>
#include <linux/statfs.h>
#include <linux/module.h>
#include <linux/file.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>

#include "ociv2.h"

#define OCIV2FS_MAGIC 0x6d65736875676761

static int squashfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	buf->f_type = OCIV2FS_MAGIC;
	buf->f_bsize = 0;
	buf->f_blocks = 0;
	buf->f_bfree = 0;
	buf->f_bavail = 0;
	buf->f_files = 0;  // TODO
	buf->f_bfree = 0;
	buf->f_namelen = PATH_MAX;
	buf->f_fsid.val[0] = 0;
	buf->f_fsid.val[1] = 0;

	return 0;
}

static void ociv2fs_put_super(struct super_block *sb)
{
	struct ociv2fs *fs = sb->s_fs_info;

	if (!fs)
		return;

	if (fs->oci_dir)
		fput(fs->oci_dir);

	kfree(fs);
}

static struct inode *ociv2fs_alloc_inode(struct super_block *sb)
{
	struct ociv2fs_inode *inode;

	inode = kzalloc(sizeof(struct ociv2fs_inode), GFP_KERNEL);
	if (!inode)
		return NULL;

	/* TODO: use a cache */
	return &inode->vfs;
}

static void ociv2fs_free_inode(struct inode *inode)
{
	kfree(inode);
}

static const struct super_operations ociv2fs_super_ops = {
	.alloc_inode = ociv2fs_alloc_inode,
	.free_inode = ociv2fs_free_inode,
	.statfs = squashfs_statfs,
	.put_super = ociv2fs_put_super,
};

static int ociv2fs_fill_super(struct super_block *sb, struct fs_context *fc)
{
	struct ociv2fs *fs;
	struct ociv2fs_ctx *ctx = fc->fs_private;
	struct inode *root;
	int err;


	fs = kzalloc(sizeof(*fs), GFP_KERNEL);
	if (!fs)
		return -ENOMEM;
	xa_init(&fs->inodes);

	sb->s_fs_info = fs;
	sb->s_op = &ociv2fs_super_ops;

	fs->oci_dir = filp_open(fc->source, O_PATH, 0);
	fs->name = ctx->name;

	/*
	 * TODO: if verify = true, we should verify everything when we open it,
	 * IMA style.
	 */

	err = populate_ociv2_metadata(fs);
	if (err < 0)
		goto fail_freefs;

	root = new_inode(sb);
	if (!root) {
		err = -ENOMEM;
		goto fail_freefs;
	}

	err = read_inode(fs, root, 1);
	if (err) {
		make_bad_inode(root);
		iput(root);
		goto fail_freefs;
	}

	sb->s_root = d_make_root(root);
	if (!sb->s_root) {
		err = -ENOMEM;
		goto fail_freefs;
	}

	return 0;

fail_freefs:
	kfree(fs);
	return err;
}

enum proc_param {
	Opt_verify,
	Opt_name,
};

static const struct fs_parameter_spec ociv2fs_parameters[] = {
	fsparam_bool("verify",	Opt_verify),
	fsparam_string("name",	Opt_name),
	{},
};

static int ociv2fs_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
	struct ociv2fs_ctx *ctx = fc->fs_private;
	struct fs_parse_result result;
	int opt;

	opt = fs_parse(fc, ociv2fs_parameters, param, &result);
	if (opt < 0)
		return opt;

	switch (opt) {
	case Opt_verify:
		ctx->verify = result.boolean;
		break;
	case Opt_name:
		ctx->name = param->string;
		param->string = NULL;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static void ociv2fs_context_free(struct fs_context *fc)
{
	struct ociv2fs_ctx *ctx = fc->fs_private;

	if (ctx->name)
		kfree(ctx->name);

	kfree(ctx);
}

static int ociv2fs_get_tree(struct fs_context *fc)
{
	return get_tree_nodev(fc, ociv2fs_fill_super);
}

static int ociv2fs_reconfigure(struct fs_context *fc)
{
	struct super_block *sb = fc->root->d_sb;

	sync_filesystem(sb);
	fc->sb_flags |= SB_RDONLY;
	return 0;
}

static const struct fs_context_operations ociv2fs_context_ops = {
	.free		= ociv2fs_context_free,
	.parse_param	= ociv2fs_parse_param,
	.get_tree	= ociv2fs_get_tree,
	.reconfigure	= ociv2fs_reconfigure,
};

static int ociv2fs_init_context(struct fs_context *fc)
{
	struct ociv2fs_ctx *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	fc->fs_private = ctx;
	fc->ops = &ociv2fs_context_ops;
	return 0;
}

static void ociv2fs_kill_sb(struct super_block *sb)
{
	kill_anon_super(sb);
}

static struct file_system_type ociv2fs_type = {
	.name			= "ociv2fs",
	.init_fs_context	= ociv2fs_init_context,
	.parameters		= ociv2fs_parameters,
	.kill_sb		= ociv2fs_kill_sb,
};

static int __init ociv2fs_init(void)
{
	return register_filesystem(&ociv2fs_type);
}

static void __exit ociv2fs_exit(void)
{
	unregister_filesystem(&ociv2fs_type);
}

module_init(ociv2fs_init);
module_exit(ociv2fs_exit);
MODULE_ALIAS_FS("ociv2fs");
MODULE_DESCRIPTION("ociv2fs for mounting OCIv2 images directly");
MODULE_LICENSE("GPL");
