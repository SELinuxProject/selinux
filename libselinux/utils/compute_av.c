#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <selinux/selinux.h>

int main(int argc, char **argv)
{
	struct av_decision avd;
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

	ret = security_compute_av(argv[1], argv[2], tclass, 1, &avd);
	if (ret < 0) {
		fprintf(stderr, "%s:  security_compute_av failed\n", argv[0]);
		exit(3);
	}

	printf("allowed=");
	print_access_vector(tclass, avd.allowed);
	printf("\n");

	if (avd.decided != ~0U) {
		printf("decided=");
		print_access_vector(tclass, avd.decided);
		printf("\n");
	}

	if (avd.auditallow) {
		printf("auditallow=");
		print_access_vector(tclass, avd.auditallow);
		printf("\n");
	}

	if (avd.auditdeny != ~0U) {
		printf("auditdeny");
		print_access_vector(tclass, avd.auditdeny);
		printf("\n");
	}

	exit(EXIT_SUCCESS);
}
