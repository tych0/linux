#include <linux/string.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/module.h>

#include "cbor.h"

static int basic_string_test(void)
{
	char buf[] = {0x64, 0x61, 0x73, 0x64, 0x66};
	struct cbor cbor;
	struct cbor_value v;
	int err;

	init_cbor(&cbor, buf, sizeof(buf));
	err = next(&cbor, &v);
	if (err < 0)
		goto out;

	err = -EINVAL;
	if (v.major != cbor_string) {
		pr_err("failed to parse string\n");
		goto out;
	}

	if (v.length != 4) {
		pr_err("failed to parse string length\n");
		goto out;
	}

	if (strncmp(v.buf, "asdf", 4)) {
		pr_err("didn't get \"asdf\" for string\n");
		goto out;
	}

	err = 0;
out:
	return err;
}

static int basic_int_test(void)
{
	struct {
		char buf[9];
		u64 len;
		u64 val;
	} int_tests[] = {
		{{0x05}, 1, 5L},
		{{0x18, 0x23}, 2, 35L},
		{{0x38, 0x22}, 2, 35L}, /* negative */
		{{0x19, 0x01, 0xf4}, 3, 500L},
		{{0x1a, 0x01, 0x00, 0x00, 0x00, 0x00}, 5, 16777216L}, /* 2**24 */
		{{0x1b, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00}, 9, 8589934592L}, /* 2**33 */
	};
	int i;
	int failed = 0;

	for (i = 0; i < ARRAY_SIZE(int_tests); i++) {
		struct cbor cbor;
		struct cbor_value v;
		int err;

		init_cbor(&cbor, int_tests[i].buf, int_tests[i].len);
		err = next(&cbor, &v);
		if (err < 0) {
			failed++;
			pr_err("error (%d) reading int test %llu\n", err, int_tests[i].val);
			continue;
		}

		if (v.major != cbor_uint && v.major != cbor_nint) {
			failed++;
			pr_err("error in int test major type %llu\n", int_tests[i].val);
			continue;
		}

		if (v.val != int_tests[i].val) {
			failed++;
			pr_err("int test fail: %llu != %llu\n", v.val, int_tests[i].val);
		}
	}

	if (failed > 0)
		return -1;
	return 0;
}

static int int_array_test(void)
{
	char buf[] = {0x83, 0x01, 0x02, 0x18, 0x32};
	u64 *result;
	struct cbor cbor;
	struct cbor_value cur;
	int err;

	init_cbor(&cbor, buf, sizeof(buf));
	err = next(&cbor, &cur);
	if (err < 0) {
		pr_err("parsing int array failed %d\n", err);
		return err;
	}

	if (cur.length != 3) {
		pr_err("array length didn't match: %llu\n", cur.length);
		return -EINVAL;
	}

	result = decode_int_array(&cbor, cur.length);
	if (IS_ERR(result)) {
		pr_err("decoding int array failed %ld\n", PTR_ERR(result));
		return PTR_ERR(result);
	}

	if (result[0] != 1) {
		pr_err("result[0] bad: %llu\n", result[0]);
		return -EINVAL;
	}

	if (result[1] != 2) {
		pr_err("result[1] bad: %llu\n", result[1]);
		return -EINVAL;
	}

	if (result[2] != 50) {
		pr_err("result[2] bad: %llu\n", result[2]);
		return -EINVAL;
	}

	return 0;
}

static int string_array_test(void)
{
	char buf[] = {0x82, 0x69, 0x6D, 0x65, 0x73, 0x68, 0x75, 0x67, 0x67,
		      0x61, 0x68, 0x65, 0x72, 0x6F, 0x63, 0x6B, 0x73};
	char **result;
	struct cbor cbor;
	struct cbor_value cur;
	int err;

	init_cbor(&cbor, buf, sizeof(buf));

	err = next(&cbor, &cur);
	if (err < 0) {
		pr_err("parsing string array failed %d\n", err);
		return err;
	}

	if (cur.length != 2) {
		pr_err("array length didn't match: %llu\n", cur.length);
		return -EINVAL;
	}

	result = decode_bytes_array(&cbor, cur.length);
	if (IS_ERR(result)) {
		pr_err("decoding string array failed %ld\n", PTR_ERR(result));
		return PTR_ERR(result);
	}

	if (strcmp(result[0], "meshuggah")) {
		pr_err("result[0] didn't match: %s\n", result[0]);
		return -EINVAL;
	}

	if (strcmp(result[1], "rocks")) {
		pr_err("result[1] didn't match: %s\n", result[1]);
		return -EINVAL;
	}

	return 0;
}

static int map_test(void)
{
	char buf[] = {0xa2, 0x68, 0x62, 0x69, 0x63, 0x79, 0x63, 0x6C, 0x65,
		      0x73, 0x64, 0x67, 0x6F, 0x6F, 0x64, 0x64, 0x63, 0x61,
		      0x72, 0x73, 0x63, 0x62, 0x61, 0x64};
	struct cbor_map_entry *result;
	struct cbor cbor;
	struct cbor_value cur;
	int err;

	init_cbor(&cbor, buf, sizeof(buf));
	err = next(&cbor, &cur);
	if (err < 0) {
		pr_err("parsing map failed %d\n", err);
		return err;
	}

	if (cur.length != 2) {
		pr_err("map length didn't match: %llu\n", cur.length);
		return -EINVAL;
	}

	result = decode_map_array(&cbor, cur.length);
	if (IS_ERR(result)) {
		pr_err("decoding map failed %ld\n", PTR_ERR(result));
		return PTR_ERR(result);
	}

	if (strcmp(result[0].key, "bicycles") || strcmp(result[0].val, "good")) {
		pr_err("result[0] didn't match: %s: %s\n", result[0].key, result[0].val);
		return -EINVAL;
	}

	if (strcmp(result[1].key, "cars") || strcmp(result[1].val, "bad")) {
		pr_err("result[1] didn't match: %s: %s\n", result[1].key, result[1].val);
		return -EINVAL;
	}

	return 0;
}

static int (*tests[])(void) = {
	basic_string_test,
	basic_int_test,
	int_array_test,
	string_array_test,
	map_test,
	NULL
};

static int __init cbor_test_init(void)
{
	int i;
	int failed = 0;

	for (i = 0; tests[i]; i++) {
		int err = tests[i]();
		if (err < 0)
			failed++;
	}

	if (failed) {
		pr_err("TYCHO: %d tests failed\n", failed);
		return -1;
	} else {
		pr_err("TYCHO: cbor tests passed\n");
	}

	return 0;
}

static void __exit cbor_test_exit(void)
{
	// no-op
}


module_init(cbor_test_init);
module_exit(cbor_test_exit);
MODULE_DESCRIPTION("cbor self tests");
MODULE_LICENSE("GPL");
