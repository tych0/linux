// SPDX-License-Identifier: GPL-2.0
/*
 * A CBOR https://tools.ietf.org/html/rfc7049 parser.
 */
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/byteorder/generic.h>

#include "cbor.h"

#define CBOR_MAJOR(b)	(((unsigned char)b) >> 5)
#define CBOR_ADDL(b)	((b) & 0x1F)

static int read_length(struct cbor *cbor, enum cbor_major *major, u64 *length)
{
	char b;

	if (cbor->offset+1 > cbor->len)
		return -EINVAL;
	b = cbor->buf[cbor->offset++];

	/* find out the type */
	*major = CBOR_MAJOR(b);

	/* find out the length */
	switch (CBOR_ADDL(b)) {
	case 24:
		if (cbor->offset+1 > cbor->len)
			return -EINVAL;
		*length = cbor->buf[cbor->offset++];
		break;
	case 25:
		if (cbor->offset+2 > cbor->len)
			return -EINVAL;
		*length = be16_to_cpu(*((__be16*)(cbor->buf + cbor->offset)));
		cbor->offset += 2;
		break;
	case 26:
		if (cbor->offset+4 > cbor->len)
			return -EINVAL;
		*length = be32_to_cpu(*((__be32*)(cbor->buf + cbor->offset)));
		cbor->offset += 4;
		break;
	case 27:
		if (cbor->offset+8 > cbor->len)
			return -EINVAL;
		*length = be64_to_cpu(*((__be64*)(cbor->buf + cbor->offset)));
		cbor->offset += 8;
		break;
	case 28:
		/* fallthrough */
	case 29:
		/* fallthrough */
	case 30:
		return -EINVAL;
	case 31:
		/* indefinite length */
		return -ENOSYS;
	default:
		*length = CBOR_ADDL(b);
	}

	return 0;
}

/* type safety for generic code in C, whee */
#define DEFINE_ARRAY_DECODE(typ, name, decode_f, release_f)			\
	typ *decode_##name##_array(struct cbor *cbor, u64 len)			\
	{									\
		int err;							\
		u64 i;								\
		typ *ret;							\
										\
		/* reject zero length arrays, they don't have a type. */	\
		if (len == 0)							\
			return ERR_PTR(-EINVAL);				\
										\
		ret = kzalloc(sizeof(*ret) * len, GFP_KERNEL);			\
		if (!ret)							\
			return ERR_PTR(-ENOMEM);				\
										\
		for (i = 0; i < len; i++) {					\
			err = decode_f(cbor, &ret[i]);				\
			if (err)						\
				goto err;					\
		}								\
										\
		return ret;							\
	err:									\
		for (i = 0; i < len; i++) {					\
			release_f(ret[i]);					\
		}								\
		kfree(ret);							\
		return ERR_PTR(err);						\
	}

int decode_int(struct cbor *cbor, u64 *val)
{
	int err;
	struct cbor_value cur;

	err = next(cbor, &cur);
	if (err < 0)
		return err;

	if (cur.major != cbor_uint && cur.major != cbor_nint)
		return -EINVAL;

	*val = cur.val;
	return 0;
}

static void release_int(u64 unused)
{
	// no-op
}
DEFINE_ARRAY_DECODE(u64, int, decode_int, release_int);

int decode_bytes(struct cbor *cbor, char **val)
{
	int err;
	struct cbor_value cur;

	err = next(cbor, &cur);
	if (err < 0)
		return err;

	if (cur.major != cbor_bytes && cur.major != cbor_string)
		return -EINVAL;

	*val = kmemdup_nul(cur.buf, cur.length, GFP_KERNEL);
	if (!*val)
		return -ENOMEM;

	return 0;
}
DEFINE_ARRAY_DECODE(char *, bytes, decode_bytes, kfree);

void release_bytes_array(char **arr, u64 len)
{
	u64 i;

	for (i = 0; i < len; i++)
		kfree(arr[i]);
	kfree(arr);
}

static int decode_map(struct cbor *cbor, struct cbor_map_entry *val)
{
	int err;
	struct cbor_value cur;

	err = next(cbor, &cur);
	if (err < 0)
		return err;

	if (cur.major != cbor_bytes && cur.major != cbor_string)
		return -EINVAL;

	val->key = kmemdup_nul(cur.buf, cur.length, GFP_KERNEL);
	if (!val->key)
		return -ENOMEM;

	err = next(cbor, &cur);
	if (err < 0)
		goto err_free_key;

	err = -EINVAL;
	if (cur.major != cbor_bytes && cur.major != cbor_string)
		goto err_free_key;

	err = -ENOMEM;
	val->val = kmemdup_nul(cur.buf, cur.length, GFP_KERNEL);
	if (!val->val)
		goto err_free_key;

	return 0;

err_free_key:
	kfree(val->key);
	return err;
}

static void release_map(struct cbor_map_entry m)
{
	kfree(m.key);
	kfree(m.val);
}

DEFINE_ARRAY_DECODE(struct cbor_map_entry, map, decode_map, release_map);

void release_map_array(struct cbor_map_entry *array, u64 len)
{
	u64 i;

	for (i = 0; i < len; i++)
		release_map(array[i]);
	kfree(array);
}

int decode_generic_map(struct cbor *cbor, map_decoder_t decoder_f, void *user)
{
	struct cbor_value v;
	int err;

	err = next(cbor, &v);
	if (err < 0) {
		return err;
	}

	if (v.major != cbor_map)
		return -EINVAL;

	return decode_generic_map_len(v.length, cbor, decoder_f, user);
}

int decode_generic_map_len(u64 len, struct cbor *cbor, map_decoder_t decoder_f, void *user)
{
	u64 i;

	for (i = 0; i < len; i++) {
		struct cbor_value key = {};
		int err;

		err = next(cbor, &key);
		if (err < 0) {
			return err;
		}

		err = decoder_f(cbor, i, &key, user);
		if (err < 0) {
			return err;
		}
	}

	return 0;
}

int next(struct cbor *cbor, struct cbor_value *cur)
{
	int err;

	err = read_length(cbor, &cur->major, &cur->length);
	if (err)
		return err;

	/* find out the value */
	switch (cur->major) {
	case cbor_uint:
		/*
		 * The uint encoding is the same as the length encoding, which
		 * means we can just copy out our already computed length as
		 * the value.
		 */
		cur->val = cur->length;
		break;
	case cbor_nint:
		/*
		 * The sint encoding is -1 - encoded integer, which is the same
		 * as the length encoding. The sign is indicated by the major
		 * type, so the magnitude is really 1 + the encoded integer.
		 */
		cur->val = 1 + cur->length;
		break;
	case cbor_bytes:
		/* fallthrough */
	case cbor_string:
		cur->buf = cbor->buf + cbor->offset;
		cbor->offset += cur->length;
		break;
	case cbor_array:
		/* fallthrough */
	case cbor_map:
		/* length and major are the only immediate outputs */
		break;
	default:
		return -ENOSYS;
	}

	return 0;
}
