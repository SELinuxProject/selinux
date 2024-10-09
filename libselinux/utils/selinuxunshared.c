#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <selinux/selinux.h>

int main(int argc, char **argv)
{
	int ret;

	if (argc != 1) {
		fprintf(stderr, "usage: %s\n", argv[0]);
		exit(-1);
	}

	ret = is_selinux_unshared();
	if (ret < 0) {
		perror(argv[0]);
		exit(-1);
	}

	printf("%d\n", ret);

	exit(!ret);
}
