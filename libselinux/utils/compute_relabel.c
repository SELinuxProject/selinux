#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <selinux/selinux.h>

int main(int argc, char **argv)
{
	char *buf;
	security_class_t tclass;
	int ret;

	if (argc != 4) {
		fprintf(stderr, "usage:  %s scontext tcontext tclass\n",
			argv[0]);
		exit(1);
	}

	tclass = string_to_security_class(argv[3]);
	if (!tclass) {
		fprintf(stderr, "%s:  invalid class '%s'\n", argv[0], argv[3]);
		exit(2);
	}

	ret = security_compute_relabel(argv[1], argv[2], tclass, &buf);
	if (ret < 0) {
		fprintf(stderr, "%s:  security_compute_relabel failed\n",
			argv[0]);
		exit(3);
	}

	printf("%s\n", buf);
	freecon(buf);
	exit(0);
}
