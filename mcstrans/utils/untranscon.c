#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <selinux/selinux.h>
#include "mcstrans.h"

static __attribute__((__noreturn__)) void usage(const char *progname)
{
	fprintf(stderr, "usage:  %s context\n", progname);
	exit(1);
}
int main(int argc, char **argv) {
	security_context_t scon;
	if ( argc != 2 ) usage(argv[0]);
	if (init_translations()==0) {
		if(untrans_context(argv[1],&scon) == 0) {
			printf("%s\n", scon);
			freecon(scon);
			return 0;
		}
	}
	return -1;
}


