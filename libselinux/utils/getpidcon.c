#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <selinux/selinux.h>

int main(int argc, char **argv)
{
	pid_t pid;
	char *buf;
	int rc;

	if (argc != 2) {
		fprintf(stderr, "usage:  %s pid\n", argv[0]);
		exit(1);
	}

	if (sscanf(argv[1], "%d", &pid) != 1) {
		fprintf(stderr, "%s:  invalid pid %s\n", argv[0], argv[1]);
		exit(2);
	}

	rc = getpidcon(pid, &buf);
	if (rc < 0) {
		fprintf(stderr, "%s:  getpidcon() failed\n", argv[0]);
		exit(3);
	}

	printf("%s\n", buf);
	freecon(buf);
	exit(0);
}
