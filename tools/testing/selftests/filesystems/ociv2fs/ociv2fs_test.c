// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include "../../kselftest.h"

#define ARRAY_SIZE(a)    (sizeof(a) / sizeof(a[0]))

static int ociv2fs_mount_test(void)
{
	char dir[] = P_tmpdir "/ociv2fs_XXXXXX";
	int ret, i;
	DIR *the_dir;
	char path[256];
	char *dirents[] = {
		"foo",
		"bar",
	};

	if (!mkdtemp(dir))
		ksft_exit_fail_msg("%s - failed to create mountpoint\n",
				   strerror(errno));

	ret = mount("./basic", dir, "ociv2fs", 0, "name=test");
	if (ret < 0)
		ksft_exit_fail_msg("%s - failed to mount\n", strerror(errno));

	the_dir = opendir(dir);
	if (!the_dir)
		ksft_exit_fail_msg("%s - failed to open %s\n", strerror(errno),
				   dir);

	for (i = 0; i < ARRAY_SIZE(dirents); i++) {
		struct dirent *ent;

		errno = 0;
		ent = readdir(the_dir);
		if (errno != 0)
			ksft_exit_fail_msg("%s - failed to readdir\n",
					   strerror(errno));
		if (!ent)
			ksft_exit_fail_msg("didn't get enough entries\n");
		if (strcmp(ent->d_name, dirents[i]))
			ksft_exit_fail_msg("%dth dirent mismatch %s %s\n", i,
					   ent->d_name, dirents[i]);
	}

	for (i = 0; i < ARRAY_SIZE(dirents); i++) {
		int fd, n;
		char buf[4];

		snprintf(path, sizeof(path), "%s/%s", dir, dirents[i]);
		fd = open(path, O_RDONLY);
		if (fd < 0)
			ksft_exit_fail_msg("%s failed to open %s", strerror(errno),
					   dirents[i]);

		n = read(fd, buf, sizeof(buf));
		close(fd);
		if (sizeof(buf)-1 != n)
			ksft_exit_fail_msg("failed to read %s (%d)\n", dirents[i], n);
		buf[sizeof(buf)-1] = 0;
		if (strncmp(buf, "baz", 3))
			ksft_exit_fail_msg("%s mismatch: %s %s\n", dirents[i], buf, "baz");
	}

	ksft_inc_pass_cnt();

	return 0;
}

int main(int argc, char *argv[])
{
	ksft_set_plan(1);
	ociv2fs_mount_test();
	ksft_exit_pass();
}
