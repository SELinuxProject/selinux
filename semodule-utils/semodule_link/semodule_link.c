/* Authors: Karl MacMillan <kmacmillan@tresys.com>
 *
 * Copyright (C) 2004 Tresys Technology, LLC
 *	This program is free software; you can redistribute it and/or modify
 *  	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, version 2.
 */

#include <sepol/module.h>

#include <getopt.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define LINKPOLICY_VERSION "1.0"

char *progname;
extern char *optarg;
extern int optind;

static __attribute__((__noreturn__)) void usage(const char *program_name)
{
	printf("usage: %s [-Vv] [-o outfile] basemodpkg modpkg1 [modpkg2]...\n",
	       program_name);
	exit(1);
}

static sepol_module_package_t *load_module(char *filename)
{
	int ret;
	FILE *fp = NULL;
	struct sepol_policy_file *pf = NULL;
	sepol_module_package_t *p = NULL;

	if (sepol_module_package_create(&p)) {
		fprintf(stderr, "%s:  Out of memory\n", progname);
		goto bad;
	}
	if (sepol_policy_file_create(&pf)) {
		fprintf(stderr, "%s:  Out of memory\n", progname);
		goto bad;
	}
	fp = fopen(filename, "r");
	if (!fp) {
		fprintf(stderr, "%s:  Could not open package %s:  %s", progname,
			filename, strerror(errno));
		goto bad;
	}
	sepol_policy_file_set_fp(pf, fp);

	printf("%s:  loading package from file %s\n", progname, filename);

	ret = sepol_module_package_read(p, pf, 0);
	if (ret) {
		fprintf(stderr, "%s:  Error while reading package from %s\n",
			progname, filename);
		goto bad;
	}
	fclose(fp);
	sepol_policy_file_free(pf);
	return p;
      bad:
	sepol_module_package_free(p);
	sepol_policy_file_free(pf);
	if (fp)
		fclose(fp);
	return NULL;
}

int main(int argc, char **argv)
{
	int ch, i, show_version = 0, verbose = 0, num_mods;
	char *basename, *outname = NULL;
	sepol_module_package_t *base, **mods;
	FILE *outfile;
	struct sepol_policy_file *pf;

	progname = argv[0];

	while ((ch = getopt(argc, argv, "o:Vv")) != EOF) {
		switch (ch) {
		case 'V':
			show_version = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'o':
			outname = optarg;
			break;
		default:
			usage(argv[0]);
		}
	}

	if (show_version) {
		printf("%s\n", LINKPOLICY_VERSION);
		exit(0);
	}

	/* check args */
	if (argc < 3 || !(optind != (argc - 1))) {
		fprintf(stderr,
			"%s:  You must provide the base module package and at least one other module package\n",
			argv[0]);
		usage(argv[0]);
	}

	basename = argv[optind++];
	base = load_module(basename);
	if (!base) {
		fprintf(stderr,
			"%s:  Could not load base module from file %s\n",
			argv[0], basename);
		exit(1);
	}

	num_mods = argc - optind;
	mods =
	    (sepol_module_package_t **) malloc(sizeof(sepol_module_package_t *)
					       * num_mods);
	if (!mods) {
		fprintf(stderr, "%s:  Out of memory\n", argv[0]);
		exit(1);
	}
	memset(mods, 0, sizeof(sepol_module_package_t *) * num_mods);

	for (i = 0; optind < argc; optind++, i++) {
		mods[i] = load_module(argv[optind]);
		if (!mods[i]) {
			fprintf(stderr,
				"%s:  Could not load module from file %s\n",
				argv[0], argv[optind]);
			exit(1);
		}
	}

	if (sepol_link_packages(NULL, base, mods, num_mods, verbose)) {
		fprintf(stderr, "%s:  Error while linking packages\n", argv[0]);
		exit(1);
	}

	if (outname) {
		outfile = fopen(outname, "w");
		if (!outfile) {
			perror(outname);
			exit(1);
		}

		if (sepol_policy_file_create(&pf)) {
			fprintf(stderr, "%s:  Out of memory\n", argv[0]);
			exit(1);
		}
		sepol_policy_file_set_fp(pf, outfile);
		if (sepol_module_package_write(base, pf)) {
			fprintf(stderr, "%s:  Error writing linked package.\n",
				argv[0]);
			exit(1);
		}
		sepol_policy_file_free(pf);
		fclose(outfile);
	}

	sepol_module_package_free(base);
	for (i = 0; i < num_mods; i++)
		sepol_module_package_free(mods[i]);
	free(mods);
	exit(0);
}
