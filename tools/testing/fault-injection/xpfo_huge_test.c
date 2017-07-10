#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#define DEV "/dev/xpfoht"
#define XPFO_IOCTL_READ 6969


int main() {
	int flags, fd, ret = 1, size = getpagesize();
	char *b;

	fd = open(DEV, O_RDWR);
	if (fd == -1) {
		perror("open");
		return -1;
	}

	flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB;
	b = mmap(NULL, size * 20, PROT_WRITE | PROT_READ, flags, 0, 0);
	printf("addr: %p\n", b);
	if (b == MAP_FAILED) {
		perror("mmap");
		goto out_c;
	}

	/* make sure the page is actually used */
	b[0] = 0;

	system("grep -i Hugepage /proc/meminfo");

	ret = ioctl(fd, XPFO_IOCTL_READ, b);
	if (ret < 0) {
		printf("Error on ioctl: %d\n", errno);
		goto out_um;
	}


	printf("ioctl returned: %d\n", ret);
	ret = 0;

out_um:
	munmap(b, size*20);
out_c:
	close(fd);
	return ret;
}
