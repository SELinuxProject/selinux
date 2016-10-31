/* Authors: Karl MacMillan <kmacmillan@tresys.com>
 * 	    Joshua Brindle <jbrindle@tresys.com>
 *
 * Copyright (C) 2004 Tresys Technology, LLC
 *	This program is free software; you can redistribute it and/or modify
 *  	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, version 2.
 */

#include <sepol/policydb.h>
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

extern char *optarg;
extern int optind;

int policyvers = 0;

#define EXPANDPOLICY_VERSION "1.0"

static void usage(char *program_name)
{
	printf("usage: %s [-V -a -c [version]] basemodpkg outputfile\n",
	       program_name);
	exit(1);
}

int main(int argc, char **argv)
{
	char *basename, *outname;
	int ch, ret, show_version = 0, verbose = 0;
	struct sepol_policy_file *pf;
	sepol_module_package_t *base;
	sepol_policydb_t *out, *p;
	FILE *fp, *outfile;
	int check_assertions = 1;
	sepol_handle_t *handle;

	while ((ch = getopt(argc, argv, "c:Vva")) != EOF) {
		switch (ch) {
		case 'V':
			show_version = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'c':{
				long int n = strtol(optarg, NULL, 10);
				if (errno) {
					fprintf(stderr,
						"%s:  Invalid policyvers specified: %s\n",
						argv[0], optarg);
					usage(argv[0]);
					exit(1);
				}
				if (n < sepol_policy_kern_vers_min()
				    || n > sepol_policy_kern_vers_max()) {
					fprintf(stderr,
						"%s:  policyvers value %ld not in range %d-%d\n",
						argv[0], n,
						sepol_policy_kern_vers_min(),
						sepol_policy_kern_vers_max());
					usage(argv[0]);
					exit(1);
				}
				policyvers = n;
				break;
			}
		case 'a':{
				check_assertions = 0;
				break;
			}
		default:
			usage(argv[0]);
		}
	}

	if (verbose) {
		if (policyvers)
			printf("Building version %d policy\n", policyvers);
	}

	if (show_version) {
		printf("%s\n", EXPANDPOLICY_VERSION);
		exit(0);
	}

	/* check args */
	if (argc < 3 || !(optind != (argc - 1))) {
		fprintf(stderr,
			"%s:  You must provide the base module package and output filename\n",
			argv[0]);
		usage(argv[0]);
	}

	basename = argv[optind++];
	outname = argv[optind];

	handle = sepol_handle_create();
	if (!handle)
		exit(1);

	if (sepol_policy_file_create(&pf)) {
		fprintf(stderr, "%s:  Out of memory\n", argv[0]);
		exit(1);
	}

	/* read the base module */
	if (sepol_module_package_create(&base)) {
		fprintf(stderr, "%s:  Out of memory\n", argv[0]);
		exit(1);
	}
	fp = fopen(basename, "r");
	if (!fp) {
		fprintf(stderr, "%s:  Can't open '%s':  %s\n",
			argv[0], basename, strerror(errno));
		exit(1);
	}
	sepol_policy_file_set_fp(pf, fp);
	ret = sepol_module_package_read(base, pf, 0);
	if (ret) {
		fprintf(stderr, "%s:  Error in reading package from %s\n",
			argv[0], basename);
		exit(1);
	}
	fclose(fp);

	/* linking the base takes care of enabling optional avrules */
	p = sepol_module_package_get_policy(base);
	if (sepol_link_modules(handle, p, NULL, 0, 0)) {
		fprintf(stderr, "%s:  Error while enabling avrules\n", argv[0]);
		exit(1);
	}

	/* create the output policy */

	if (sepol_policydb_create(&out)) {
		fprintf(stderr, "%s:  Out of memory\n", argv[0]);
		exit(1);
	}

	sepol_set_expand_consume_base(handle, 1);

	if (sepol_expand_module(handle, p, out, verbose, check_assertions)) {
		fprintf(stderr, "%s:  Error while expanding policy\n", argv[0]);
		exit(1);
	}

	if (policyvers) {
		if (sepol_policydb_set_vers(out, policyvers)) {
			fprintf(stderr, "%s:  Invalid version %d\n", argv[0],
				policyvers);
			exit(1);
		}
	}

	sepol_module_package_free(base);

	outfile = fopen(outname, "w");
	if (!outfile) {
		perror(outname);
		exit(1);
	}

	sepol_policy_file_set_fp(pf, outfile);
	ret = sepol_policydb_write(out, pf);
	if (ret) {
		fprintf(stderr,
			"%s:  Error while writing expanded policy to %s\n",
			argv[0], outname);
		exit(1);
	}
	fclose(outfile);
	sepol_handle_destroy(handle);
	sepol_policydb_free(out);
	sepol_policy_file_free(pf);

	return 0;
}
