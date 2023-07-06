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

static void usage(const char *progname)
{
	printf("usage: %s ppfile modfile [fcfile]\n", progname);
}

int main(int argc, char **argv)
{
	struct sepol_module_package *pkg = NULL;
	struct sepol_policy_file *in = NULL, *out = NULL;
	FILE *fp = NULL;
	size_t len;
	const char *ppfile, *modfile, *fcfile = NULL, *fcdata;
	int ret;

	if (argc < 3) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	ppfile = argv[1];
	modfile = argv[2];
	if (argc >= 4)
		fcfile = argv[3];

	if (sepol_module_package_create(&pkg)) {
		fprintf(stderr, "%s:  Out of memory\n", argv[0]);
		goto failure;
	}

	if (sepol_policy_file_create(&in)) {
		fprintf(stderr, "%s:  Out of memory\n", argv[0]);
		goto failure;
	}

	fp = fopen(ppfile, "r");
	if (!fp) {
		fprintf(stderr, "%s:  Could not open file %s:  %s\n", argv[0], ppfile, strerror(errno));
		goto failure;
	}
	sepol_policy_file_set_fp(in, fp);

	if (sepol_module_package_read(pkg, in, 0) == -1) {
		fprintf(stderr, "%s:  Error while reading policy module from %s\n",
			argv[0], ppfile);
		goto failure;
	}

	sepol_policy_file_free(in);
	in = NULL;
	fclose(fp);
	fp = NULL;

	if (sepol_policy_file_create(&out)) {
		fprintf(stderr, "%s:  Out of memory\n", argv[0]);
		goto failure;
	}

	fp = fopen(modfile, "w");
	if (!fp) {
		fprintf(stderr, "%s:  Could not open file %s:  %s\n", argv[0], modfile, strerror(errno));
		goto failure;
	}
	sepol_policy_file_set_fp(out, fp);

	if (sepol_policydb_write(sepol_module_package_get_policy(pkg), out)) {
		fprintf(stderr, "%s:  Error while writing module to %s\n", argv[0], modfile);
		goto failure;
	}

	ret = fclose(fp);
	fp = NULL;
	if (ret) {
		fprintf(stderr, "%s:  Error while closing file %s:  %s\n", argv[0], modfile, strerror(errno));
		goto failure;
	}

	sepol_policy_file_free(out);
	out = NULL;

	len = sepol_module_package_get_file_contexts_len(pkg);
	if (fcfile && len) {
		fp = fopen(fcfile, "w");
		if (!fp) {
			fprintf(stderr, "%s:  Could not open file %s:  %s\n", argv[0], fcfile, strerror(errno));
			goto failure;
		}
		fcdata = sepol_module_package_get_file_contexts(pkg);
		if (fwrite(fcdata, 1, len, fp) != len) {
			fprintf(stderr, "%s:  Could not write file %s:  %s\n", argv[0], fcfile, strerror(errno));
			goto failure;
		}

		ret = fclose(fp);
		fp = NULL;
		if (ret) {
			fprintf(stderr, "%s:  Could not close file %s:  %s\n", argv[0], fcfile, strerror(errno));
			goto failure;
		}
	}

	ret = EXIT_SUCCESS;
	goto cleanup;

failure:
	ret = EXIT_FAILURE;

cleanup:
	if (fp)
		fclose(fp);
	sepol_policy_file_free(out);
	sepol_module_package_free(pkg);
	sepol_policy_file_free(in);

	return ret;
}
