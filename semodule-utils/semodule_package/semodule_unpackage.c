#include <sepol/module.h>
#include <getopt.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>

char *progname = NULL;
extern char *optarg;

static void usage(void)
{
	printf("usage: %s ppfile modfile [fcfile]\n", progname);
	exit(1);
}

static int file_to_policy_file(const char *filename, struct sepol_policy_file **pf, const char *mode)
{
	FILE *f;

	if (sepol_policy_file_create(pf)) {
		fprintf(stderr, "%s:  Out of memory\n", progname);
		return -1;
	}

	f = fopen(filename, mode);
	if (!f) {
		fprintf(stderr, "%s:  Could not open file %s:  %s\n", progname, strerror(errno), filename);
		return -1;
	}
	sepol_policy_file_set_fp(*pf, f);
	return 0;
}

int main(int argc, char **argv)
{
	struct sepol_module_package *pkg;
	struct sepol_policy_file *in, *out;
	FILE *fp;
	size_t len;
	char *ppfile, *modfile, *fcfile = NULL, *fcdata;

	progname = argv[0];

	if (argc < 3) {
		usage();
		exit(1);
	}

	ppfile = argv[1];
	modfile = argv[2];
	if (argc >= 3)
		fcfile = argv[3];

	if (file_to_policy_file(ppfile, &in, "r"))
		exit(1);

	if (sepol_module_package_create(&pkg)) {
                fprintf(stderr, "%s:  Out of memory\n", progname);
                exit(1);
	}

	if (sepol_module_package_read(pkg, in, 0) == -1) {
                fprintf(stderr, "%s:  Error while reading policy module from %s\n",
			progname, ppfile);
                exit(1);
	}

	if (file_to_policy_file(modfile, &out, "w"))
		exit(1);

        if (sepol_policydb_write(sepol_module_package_get_policy(pkg), out)) {
                fprintf(stderr, "%s:  Error while writing module to %s\n", progname, modfile);
                exit(1);
        }

	sepol_policy_file_free(in);
	sepol_policy_file_free(out);

	len = sepol_module_package_get_file_contexts_len(pkg);
	if (fcfile && len) {
		fp = fopen(fcfile, "w");
		if (!fp) {
			fprintf(stderr, "%s:  Could not open file %s:  %s\n", progname, strerror(errno), fcfile);
			exit(1);
		}
		fcdata = sepol_module_package_get_file_contexts(pkg);
		if (fwrite(fcdata, 1, len, fp) != len) {
			fprintf(stderr, "%s:  Could not write file %s:  %s\n", progname, strerror(errno), fcfile);
			exit(1);
		}
		fclose(fp);
	}

	sepol_module_package_free(pkg);
	exit(0);
}
