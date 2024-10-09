#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mount.h>
#include <selinux/selinux.h>

int main(int argc, char **argv)
{
	int ret;

	ret = unshare(CLONE_NEWNS);
	if (ret < 0) {
		perror("unshare(CLONE_NEWNS)");
		exit(1);
	}

	ret = mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL);
	if (ret < 0) {
		perror("mount(/)");
		exit(1);
	}

	ret = selinux_unshare();
	if (ret < 0) {
		perror("selinux_unshare");
		exit(1);
	}

	if (argc < 2) {
		fprintf(stderr, "usage: %s command args...\n", argv[0]);
		exit(1);
	}

	execvp(argv[1], &argv[1]);
	perror(argv[1]);
	exit(1);
}
