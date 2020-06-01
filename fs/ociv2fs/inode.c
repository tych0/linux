#include <linux/mm_types.h>
#include <linux/pagemap.h>

#include "ociv2.h"

static struct dentry *ociv2fs_lookup(struct inode *dir, struct dentry *dentry,
				     unsigned int flags)
{
	struct ociv2fs_inode *ocinode = ociv2fs_i(dir);
	const char *name = dentry->d_name.name;
	u64 i;
	struct inode *inode = NULL;
	struct ociv2fs *fs = dir->i_sb->s_fs_info;

	for (i = 0; i < ocinode->dir_list.len; i++) {
		struct ociv2_dir_ent *ent = &ocinode->dir_list.ents[i];
		int err;

		if (strcmp(ent->name, name))
			continue;

		inode = new_inode(dir->i_sb);
		if (!inode)
			break;

		err = read_inode(fs, inode, ent->ino);
		if (err < 0)
			return ERR_PTR(err);

		break;
	}

	return d_splice_alias(inode, dentry);
}

const struct inode_operations ociv2fs_dir_iops = {
	.lookup = ociv2fs_lookup,
};

static int ociv2fs_readdir(struct file *file, struct dir_context *ctx)
{
	struct ociv2fs_inode *ocinode = ociv2fs_i(file_inode(file));
	struct ociv2fs *fs = file_inode(file)->i_sb->s_fs_info;
	u64 i;

	if (!dir_emit_dots(file, ctx))
		return 0;

	for (i = ctx->pos-2; i < ocinode->dir_list.len; i++, ctx->pos++) {
		struct ociv2_dir_ent *ent = &ocinode->dir_list.ents[i];
		struct ociv2fs_inode *ent_inode = xa_load(&fs->inodes, ent->ino);
		int type;

		if (!ent_inode)
			return -ESRCH;

		type = ent_inode->type == ociv2_dir ? DT_DIR : DT_REG;

		if (!dir_emit(ctx, ent->name, strlen(ent->name), ent->ino, type))
			return 0;
	}

	return 0;
}

const struct file_operations ociv2fs_dir_fops = {
	.read = generic_read_dir,
	.iterate_shared = ociv2fs_readdir,
	.llseek = generic_file_llseek,
};

static int ociv2fs_readpage(struct file *file, struct page *page)
{
	struct ociv2fs_inode *ocinode = ociv2fs_i(page->mapping->host);
	void *addr;

	if (ocinode->content_len > 4096) {
		SetPageError(page);
		return 0;
	}


	if (page->index != 0) {
		SetPageError(page);
		return 0;
	} else {
		addr = kmap_atomic(page);
		memcpy(addr, ocinode->content, ocinode->content_len);
		/* should set the rest of the content to 0? */
		kunmap_atomic(addr);
	}

	flush_dcache_page(page);
	if (!PageError(page))
		SetPageUptodate(page);
	unlock_page(page);
	return 0;
}

const struct address_space_operations ociv2fs_aops = {
	.readpage = ociv2fs_readpage,
};

int read_inode(struct ociv2fs *fs, struct inode *inode, long long ino)
{
	/*
	 * cheating here: we use the same struct for the in-memory inode and
	 * the off-disk inode representation. we should not cheat.
	 */
	struct ociv2fs_inode *ocinode;

	ocinode = xa_load(&fs->inodes, ino);
	if (!ocinode)
		return -ESRCH;

	set_nlink(inode, 1);

	switch (ocinode->type) {
	case ociv2_dir:
		i_size_write(inode, 4096);
		inode->i_op = &ociv2fs_dir_iops;
		inode->i_fop = &ociv2fs_dir_fops;
		inode->i_mode = S_IFDIR;
		ociv2fs_i(inode)->dir_list = ocinode->dir_list;
		break;
	case ociv2_file:
		i_size_write(inode, ocinode->content_len);
		inode->i_fop = &generic_ro_fops;
		inode->i_mode = S_IFREG;
		inode->i_blocks = 1;
		ociv2fs_i(inode)->content_len = ocinode->content_len;
		ociv2fs_i(inode)->content = ocinode->content;
		inode->i_data.a_ops = &ociv2fs_aops;
		break;
	default:
		WARN(1, "unknown ociv2fs inode type %d\n", ocinode->type);
		return -EINVAL;
	}

	return 0;
}
