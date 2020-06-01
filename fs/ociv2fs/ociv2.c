#include <linux/slab.h>

#include "cbor.h"
#include "ociv2.h"

static int check_oci_version(struct ociv2fs *fs)
{
	char *buf = NULL;
	u64 len;
	struct cbor cbor;
	struct cbor_value root;
	int err;
	struct cbor_map_entry *map;

	/*
	 * this file is in json in v1, I guess we'd have to make it json in v2
	 * as well? use cbor for now since we have a parser for that.
	 */
	err = read_file(fs, "oci-layout", &buf, &len);
	if (err < 0)
		return err;

	init_cbor(&cbor, buf, len);
	err = next(&cbor, &root);
	if (err < 0)
		goto out_buf;

	err = -EINVAL;
	if (root.major != cbor_map || root.length != 1)
		goto out_buf;

	map = decode_map_array(&cbor, root.length);
	if (IS_ERR(map)) {
		err = PTR_ERR(map);
		goto out_buf;
	}

	if (strcmp(map[0].key, "imageLayoutVersion"))
		goto out_map;

	err = -ENOTSUPP;
	if (strcmp(map[0].val, "2.0.0"))
		goto out_map;

	err = 0;
out_map:
	release_map_array(map, root.length);
out_buf:
	kfree(buf);
	return err;
}

static int find_manifest_blob(struct ociv2fs *fs, char hash[65])
{
	struct cbor_map_entry *index;
	u64 len;
	struct cbor cbor;
	struct cbor_value root;
	int err, i;
	char *buf = NULL;

	err = read_file(fs, "index.cbor", &buf, &len);
	if (err < 0)
		return err;

	init_cbor(&cbor, buf, len);
	err = next(&cbor, &root);
	if (err < 0)
		goto out_buf;

	index = decode_map_array(&cbor, root.length);
	if (IS_ERR(index)) {
		err = PTR_ERR(index);
		goto out_buf;
	}

	err = -ESRCH;
	for (i = 0; i < root.length; i++) {
		if (strcmp(index[i].key, fs->name))
			continue;

		err = 0;
		strscpy(hash, index[i].val, 65);
		break;
	}

	release_map_array(index, root.length);
out_buf:
	kfree(buf);
	return err;
}

static int decode_dirlist(struct cbor *cbor, u64 i, struct cbor_value *key, void *user)
{
	struct ociv2fs_inode *ino = user;
	int err;
	struct cbor_value v;

	if (key->major != cbor_string)
		return -EINVAL;

	err = next(cbor, &v);
	if (err < 0)
		return -EINVAL;

	if (v.major != cbor_uint)
		return -EINVAL;

	ino->dir_list.ents[i].name = kmemdup_nul(key->buf, key->length, GFP_KERNEL);
	ino->dir_list.ents[i].ino = v.val;
	return 0;
}

static int decode_inode(struct cbor *cbor, u64 i, struct cbor_value *key, void *user)
{
	struct ociv2fs_inode *ino = user;
	int err;
	struct cbor_value v;

	switch (key->val) {
	case ociv2_inode_type: {
		err = next(cbor, &v);
		if (err < 0)
			return err;

		err = -EINVAL;
		if (v.major != cbor_uint)
			goto out;

		ino->type = v.val;
		if (ino->type != ociv2_dir && ino->type != ociv2_file)
			goto out;
		err = 0;
		break;
	}
	case ociv2_inode_file_content: {
		err = next(cbor, &v);
		if (err < 0)
			goto out;

		err = -EINVAL;
		if (ino->type != ociv2_file)
			goto out;

		if (v.major != cbor_string && v.major != cbor_bytes)
			goto out;

		ino->content = kmemdup(v.buf, v.length, GFP_KERNEL);
		ino->content_len = v.length;
		err = 0;
		break;
	}
	case ociv2_inode_dirlist: {
		err = next(cbor, &v);
		if (err < 0)
			goto out;

		err = -EINVAL;
		if (ino->type != ociv2_dir)
			goto out;

		if (v.major != cbor_map)
			goto out;

		ino->dir_list.len = v.length;
		ino->dir_list.ents = kzalloc(sizeof(*ino->dir_list.ents) * v.length, GFP_KERNEL);
		if (!ino->dir_list.ents) {
			err = -ENOMEM;
			goto out;
		}

		err = decode_generic_map_len(v.length, cbor, decode_dirlist, ino);
		if (err < 0) {
			kfree(ino->dir_list.ents);
			goto out;
		}
		err = 0;
		break;
	}
	default:
		err = -EINVAL;
	}

out:
	return err;
}

static int decode_inodes(struct ociv2fs *fs, struct cbor *cbor)
{
	struct cbor_value arr;
	int err;
	u64 i;

	err = next(cbor, &arr);
	if (err < 0) {
		return err;
	}

	if (arr.major != cbor_array) {
		return -EINVAL;
	}

	for (i = 0; i < arr.length; i++) {
		struct ociv2fs_inode *ino;


		ino = kzalloc(sizeof(*ino), GFP_KERNEL);
		if (!ino)
			return -ENOMEM;

		err = decode_generic_map(cbor, decode_inode, ino);
		if (err < 0) {
			kfree(ino);
			goto out;
		}

		if (i == 1)
		err = xa_err(xa_store(&fs->inodes, i+1, ino, GFP_KERNEL));
		if (err < 0) {
			kfree(ino->content);
			kfree(ino);
			goto out;
		}
	}

	err = 0;
out:
	return err;
}

static int manifest_decoder(struct cbor *cbor, u64 i, struct cbor_value *key, void *user)
{
	struct ociv2fs *fs = user;
	int err;

	err = -EINVAL;
	if (key->major != cbor_string) {
		return err;
	}

	if (!strncmp(key->buf, "inodes", 6)) {
		err = decode_inodes(fs, cbor);
	}
	return err;
}

// manifest's format right now is:
//
// {"inodes": [{ociv2_inode_type: ociv2_dir, ociv2_inode_dirlist: {"foo": 2, "bar": 2}},
//             {ociv2_inode_type: ociv2_file, ociv2_inode_content: "baz"}]}
static int read_manifest(struct ociv2fs *fs, char hash[65])
{
	char *buf = NULL;
	u64 len;
	struct cbor cbor;
	char path[256];
	int err;

	snprintf(path, sizeof(path), "blobs/sha256/%s", hash);

	err = read_file(fs, path, &buf, &len);
	if (err < 0) {
		return err;
	}

	init_cbor(&cbor, buf, len);
	err = decode_generic_map(&cbor, manifest_decoder, fs);
	kfree(buf);
	return err;
}

static int read_fs_metadata(struct ociv2fs *fs)
{
	char manifest[65];
	int err;

	err = find_manifest_blob(fs, manifest);
	if (err < 0)
		return err;


	err = read_manifest(fs, manifest);
	if (err < 0) {
		pr_err("error reading manifest %d\n", err);
		return err;
	}

	return 0;
}

int populate_ociv2_metadata(struct ociv2fs *fs)
{
	int err;

	err = check_oci_version(fs);
	if (err < 0)
		return err;

	err = read_fs_metadata(fs);
	if (err < 0)
		return err;

	return 0;
}
