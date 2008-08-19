#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <selinux/selinux.h>

int main(int argc, char **argv)
{
	char **buf, **ptr;
	int ret;

	if (argc != 3) {
		fprintf(stderr, "usage:  %s context user\n", argv[0]);
		exit(1);
	}

	ret = security_compute_user(argv[1], argv[2], &buf);
	if (ret < 0) {
		fprintf(stderr, "%s:  security_compute_user(%s,%s) failed\n",
			argv[0], argv[1], argv[2]);
		exit(2);
	}

	if (!buf[0]) {
		printf("none\n");
		exit(0);
	}

	for (ptr = buf; *ptr; ptr++) {
		printf("%s\n", *ptr);
	}
	freeconary(buf);
	exit(0);
}
