#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <selinux/selinux.h>

int main(int argc, char **argv)
{
	char *buf;
	int rc, i;

	if (argc < 2) {
		fprintf(stderr, "usage:  %s path...\n", argv[0]);
		exit(1);
	}

	for (i = 1; i < argc; i++) {
		rc = getfilecon(argv[i], &buf);
		if (rc < 0) {
			fprintf(stderr, "%s:  getfilecon(%s) failed\n", argv[0],
				argv[i]);
			exit(2);
		}
		printf("%s\t%s\n", argv[i], buf);
		freecon(buf);
	}
	exit(EXIT_SUCCESS);
}
