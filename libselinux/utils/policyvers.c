#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <selinux/selinux.h>

int main(int argc __attribute__ ((unused)), char **argv)
{
	int rc;

	rc = security_policyvers();
	if (rc < 0) {
		fprintf(stderr, "%s:  policyvers() failed\n", argv[0]);
		exit(2);
	}

	printf("%d\n", rc);
	exit(0);
}
