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

static void usage(const char *program_name)
{
	printf("usage: %s [-hVv] [-o outfile] basemodpkg modpkg1 [modpkg2]...\n",
	       program_name);
}

static sepol_module_package_t *load_module(const char *filename, const char *progname)
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
	fp = fopen(filename, "re");
	if (!fp) {
		fprintf(stderr, "%s:  Could not open package %s:  %s\n", progname,
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
	int ch, i, ret, show_version = 0, verbose = 0, num_mods = 0;
	const char *basename, *outname = NULL;
	sepol_module_package_t *base = NULL, **mods = NULL;
	struct sepol_policy_file *pf = NULL;

	while ((ch = getopt(argc, argv, "ho:Vv")) != EOF) {
		switch (ch) {
		case 'h':
			usage(argv[0]);
			return EXIT_SUCCESS;
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
			return EXIT_FAILURE;
		}
	}

	if (show_version) {
		printf("%s\n", LINKPOLICY_VERSION);
		return EXIT_SUCCESS;
	}

	/* check args */
	if (argc < 3 || optind + 2 > argc) {
		fprintf(stderr,
			"%s:  You must provide the base module package and at least one other module package\n",
			argv[0]);
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	basename = argv[optind++];
	base = load_module(basename, argv[0]);
	if (!base) {
		fprintf(stderr,
			"%s:  Could not load base module from file %s\n",
			argv[0], basename);
		goto failure;
	}

	num_mods = argc - optind;
	mods = calloc(num_mods, sizeof(sepol_module_package_t *));
	if (!mods) {
		fprintf(stderr, "%s:  Out of memory\n", argv[0]);
		goto failure;
	}

	for (i = 0; optind < argc; optind++, i++) {
		mods[i] = load_module(argv[optind], argv[0]);
		if (!mods[i]) {
			fprintf(stderr,
				"%s:  Could not load module from file %s\n",
				argv[0], argv[optind]);
			goto failure;
		}
	}

	if (sepol_link_packages(NULL, base, mods, num_mods, verbose)) {
		fprintf(stderr, "%s:  Error while linking packages\n", argv[0]);
		goto failure;
	}

	if (outname) {
		FILE *outfile = fopen(outname, "we");
		if (!outfile) {
			fprintf(stderr, "%s:  Could not open output file %s:  %s\n",
				argv[0], outname, strerror(errno));
			goto failure;
		}

		if (sepol_policy_file_create(&pf)) {
			fprintf(stderr, "%s:  Out of memory\n", argv[0]);
			fclose(outfile);
			goto failure;
		}
		sepol_policy_file_set_fp(pf, outfile);
		if (sepol_module_package_write(base, pf)) {
			fprintf(stderr, "%s:  Error writing linked package.\n",
				argv[0]);
			sepol_policy_file_free(pf);
			fclose(outfile);
			goto failure;
		}
		sepol_policy_file_free(pf);

		if (fclose(outfile)) {
			fprintf(stderr, "%s:  Error closing linked package:  %s\n",
				argv[0], strerror(errno));
			goto failure;
		}
	}

	ret = EXIT_SUCCESS;
	goto cleanup;

failure:
	ret = EXIT_FAILURE;

cleanup:
	if (mods) {
		for (i = 0; i < num_mods; i++)
			sepol_module_package_free(mods[i]);
		free(mods);
	}
	sepol_module_package_free(base);

	return ret;
}
