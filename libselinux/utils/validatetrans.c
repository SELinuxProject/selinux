#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <selinux/selinux.h>

int main(int argc, char **argv)
{
	security_class_t tclass;
	int ret;

	if (argc != 5) {
		fprintf(stderr, "usage:  %s scontext tcontext tclass newcontext\n",
			argv[0]);
		exit(1);
	}

	tclass = string_to_security_class(argv[3]);
	if (!tclass) {
		fprintf(stderr, "%s:  invalid class '%s'\n", argv[0], argv[3]);
		exit(2);
	}

	ret = security_validatetrans(argv[1], argv[2], tclass, argv[4]);
	printf("security_validatetrans returned %d errno: %s\n", ret, strerror(errno));

	return ret;
}
