// abandon all hope ye who enter here
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/syscalls.h>

#include "../internal.h"
#include "ociv2.h"

// the most controversial hackery whackery. it does all the bad things.
int read_file(struct ociv2fs *fs, const char *path, char **ret, u64 *len)
{
	struct file *f;
	int fd;
	struct filename *fname;
	struct open_how how = build_open_how(O_RDONLY, 0);
	struct open_flags op;
	mm_segment_t old_fs;
	ssize_t err;
	loff_t i_size;

	err = build_open_flags(&how, &op);
	if (err < 0) {
		WARN(1, "bad open flags %ld", err);
		return err;
	}

	fname = getname_kernel(path);
	if (IS_ERR(fname))
		return PTR_ERR(fname);

	/*
	 * This is a pretty brutal hack. do_filp_open() (which of course, is
	 * not exposed to modules so we have to be built-in, so we maybe
	 * shouldn't use it anyway) only accepts a dir-fd, and not a struct
	 * file*. But, we keep track of the struct file in the superblock.
	 *
	 * So, to speak do_filp_open()'s language, we create a temporary dirfd
	 * pointing to the struct file we have.
	 *
	 * Additionally, since stuff in do_filp_open()'s call path needs to
	 * create a struct file, it uses current_cred() to do it, so that means
	 * that the task triggering this metadata read needs permission to read
	 * the OCI image, otherwise it can't also do the fs read. Whee :)
	 *
	 * Maybe since we're using set_fs() later we can do something "better"
	 * here? But people aren't going to love that anyway, so...
	 */
	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		err = fd;
		goto out_fname;
	}

	if (!fs->oci_dir) {
		pr_err("missing oci dir");
		err = -EBADF;
		goto out_fname;
	}

	/* fd_install() consumes a reference to fs->oci_dir */
	fd_install(fd, get_file(fs->oci_dir));
	f = do_filp_open(fd, fname, &op);
	ksys_close(fd);
	if (IS_ERR(f)) {
		err = PTR_ERR(f);
		goto out_fname;
	}

	i_size = i_size_read(file_inode(f));
	if (i_size == 0)
		goto out_f;

	err = -ENOMEM;
	*ret = kzalloc(i_size, GFP_KERNEL);
	if (!*ret)
		goto out_f;

	/* this part is stolen from integrity_kernel_read() */
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	err = __vfs_read(f, *ret, i_size, 0);
	set_fs(old_fs);
	if (err < 0)
		goto out_f;
	if (err != i_size) {
		err = -ENOBUFS;
		WARN("couldn't read all of buffer at %s", path);
		goto out_f;
	}
	*len = err;
	err = 0;
out_f:
	fput(f);
out_fname:
	putname(fname);
	return err;
}

int read_blob(struct ociv2fs *fs, const char *blob, char **ret, u64 *len)
{
	char path[128];

	/* sha256 hex renderings are 64 bytes long */
	if (strlen(blob) != 64)
		return -EINVAL;

	snprintf(path, PATH_MAX, "/blobs/sha256/%s", blob);
	return read_file(fs, path, ret, len);
}
