// SPDX-License-Identifier: GPL-2.0

#include <linux/types.h>
#include <linux/string.h>

struct cbor {
	char *buf;
	u64 len, offset;
};

static inline void init_cbor(struct cbor *cbor, void *buf, u64 len)
{
	memset(cbor, 0, sizeof(*cbor));
	cbor->buf = buf;
	cbor->len = len;
}

enum cbor_major {
	cbor_uint = 0,
	cbor_nint = 1,
	cbor_bytes = 2,
	cbor_string = 3,
	cbor_array = 4,
	cbor_map = 5,
	cbor_tag = 6,
	cbor_float = 7,
};

struct cbor_value {
	enum cbor_major major;
	u64 length; /* INDEFINITE_LENGTH relevant for bytes, string, array, map */
	u64 offset; /* offset in the cbor's buffer */
	union {
		struct { /* uint, sint */
			u64 val;
		};

		struct { /* bytes, string */
			/*
			 * buf is used when the length is definite; use
			 * read_bytes() when the length is indefinite.
			 */
			void *buf;
		};

		/*
		 * for an array or map, use one of the array_*_decode functions
		 */
	};
};

extern int next(struct cbor *cbor, struct cbor_value *cur);

#define DECLARE_ARRAY_DECODE(typ, name) \
	extern typ *decode_##name##_array(struct cbor *cbor, u64 len)

/* free with kfree */
DECLARE_ARRAY_DECODE(u64, int);
DECLARE_ARRAY_DECODE(char *, bytes);
void release_bytes_array(char **arr, u64 len);

/*
 * as a hack, for now we treat maps as arrays, since that's how they're stored
 * on disk anyway. we can work out what needs to be sped up later, since the
 * kernel doesn't have a great data structure for this.
 *
 * we also just support string:string maps, since that's what the spec mostly
 * uses.
 */
struct cbor_map_entry {
	char *key;
	char *val;
};

/* free with release_map_array() */
DECLARE_ARRAY_DECODE(struct cbor_map_entry, map);
void release_map_array(struct cbor_map_entry *array, u64 len);

/*
 * generic decoding for maps; the decoder owns key.
 */
typedef int (*map_decoder_t)(struct cbor *cbor, u64 i, struct cbor_value *key, void *user);
int decode_generic_map(struct cbor *cbor, map_decoder_t decoder_f, void *user);
int decode_generic_map_len(u64 len, struct cbor *cbor, map_decoder_t decoder_f, void *user);

/* basic type decoding */
int decode_int(struct cbor *cbor, u64 *val);
int decode_bytes(struct cbor *cbor, char **val);
