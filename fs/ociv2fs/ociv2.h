// SPDX-License-Identifier: GPL-2.0
#include <linux/xarray.h>
#include <linux/fs.h>

struct ociv2fs_ctx {
	bool verify;
	char *name;
};

struct ociv2fs {
	/* super.c fields */
	struct file *oci_dir;
	char *name;

	/* ociv2 fields */
	struct xarray inodes;
};

struct ociv2_dir_ent {
	char *name;
	u64 ino;
};

struct ociv2_dir_list {
	struct ociv2_dir_ent *ents;
	u64 len;
};

enum ociv2_inode_info {
	ociv2_inode_type = 0,
	ociv2_inode_file_content = 1,
	ociv2_inode_dirlist = 2,
};

// TODO: this should really just be DT_DIR, etc. as define in linux/fs_types.h
enum ociv2_inode_type {
	ociv2_dir = 0,
	ociv2_file = 1,
};

struct ociv2fs_inode {
	struct inode vfs;
	enum ociv2_inode_type type;
	union {
		struct {
			struct ociv2_dir_list dir_list;
		};

		struct {
			/* file content */
			u64 content_len;
			char *content;
		};
	};
};

static inline struct ociv2fs_inode *ociv2fs_i(struct inode *inode)
{
	return container_of(inode, struct ociv2fs_inode, vfs);
}

/* user_read.c */
extern int read_file(struct ociv2fs *fs, const char *path, char **ret, u64 *len);
extern int read_blob(struct ociv2fs *fs, const char *blob, char **ret, u64 *len);

/* ociv2.c */
extern int populate_ociv2_metadata(struct ociv2fs *fs);

/* inode.c */
extern int read_inode(struct ociv2fs *fs, struct inode *inode, long long ino);
