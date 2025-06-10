/*
 * Authors: Joshua Brindle <jbrindle@tresys.com>
 *	    Karl MacMillan <kmacmillan@tresys.com>
 *          Jason Tang     <jtang@tresys.com>
 *
 *
 * Copyright (C) 2004-5 Tresys Technology, LLC
 *	This program is free software; you can redistribute it and/or modify
 *  	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, version 2.
 */

#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <sys/mman.h>
#include <libgen.h>

#include <sepol/module_to_cil.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/services.h>
#include <sepol/policydb/conditional.h>
#include <sepol/policydb/hierarchy.h>
#include <sepol/policydb/expand.h>
#include <sepol/policydb/link.h>
#include <sepol/policydb/sidtab.h>

#include "queue.h"
#include "parse_util.h"

static sidtab_t sidtab;

extern int mlspol;
extern int werror;

static int handle_unknown = SEPOL_DENY_UNKNOWN;
static const char *txtfile = "policy.conf";
static const char *binfile = "policy";

static int read_binary_policy(policydb_t * p, const char *file, const char *progname)
{
	int fd;
	struct stat sb;
	void *map;
	struct policy_file f, *fp;

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Can't open '%s':  %s\n",
			file, strerror(errno));
		return -1;
	}
	if (fstat(fd, &sb) < 0) {
		fprintf(stderr, "Can't stat '%s':  %s\n",
			file, strerror(errno));
		close(fd);
		return -1;
	}
	map =
	    mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	close(fd);
	if (map == MAP_FAILED) {
		fprintf(stderr, "Can't map '%s':  %s\n", file, strerror(errno));
		return -1;
	}
	policy_file_init(&f);
	f.type = PF_USE_MEMORY;
	f.data = map;
	f.len = sb.st_size;
	fp = &f;

	if (policydb_init(p)) {
		fprintf(stderr, "%s:  policydb_init:  Out of memory!\n",
			progname);
		return -1;
	}
	if (policydb_read(p, fp, 1)) {
		fprintf(stderr,
			"%s:  error(s) encountered while parsing configuration\n",
			progname);
		return -1;
	}

	/* Check Policy Consistency */
	if (p->mls) {
		if (!mlspol) {
			fprintf(stderr, "%s:  MLS policy, but non-MLS"
				" is specified\n", progname);
			return -1;
		}
	} else {
		if (mlspol) {
			fprintf(stderr, "%s:  non-MLS policy, but MLS"
				" is specified\n", progname);
			return -1;
		}
	}
	return 0;
}

static int write_binary_policy(policydb_t * p, FILE *outfp, unsigned int policy_type, unsigned int policyvers)
{
	struct policy_file pf;

	p->policy_type = policy_type;
	p->policyvers = policyvers;
	p->handle_unknown = handle_unknown;

	policy_file_init(&pf);
	pf.type = PF_USE_STDIO;
	pf.fp = outfp;
	return policydb_write(p, &pf);
}

static __attribute__((__noreturn__)) void usage(const char *progname)
{
	printf("usage:  %s [-h] [-V] [-b] [-C] [-E] [-U handle_unknown] [-m] [-M] [-N] [-L] [-o FILE] [-c VERSION] [INPUT]\n", progname);
	printf("Build base and policy modules.\n");
	printf("Options:\n");
	printf("  INPUT      build module from INPUT (else read from \"%s\")\n",
	       txtfile);
	printf("  -V         show policy versions created by this program\n");
	printf("  -b         treat input as a binary policy file\n");
	printf("  -C         output CIL policy instead of binary policy\n");
	printf("  -E         treat warnings as errors\n");
	printf("  -h         print usage\n");
	printf("  -U OPTION  How to handle unknown classes and permissions\n");
	printf("               deny: Deny unknown kernel checks\n");
	printf("               reject: Reject loading of policy with unknowns\n");
	printf("               allow: Allow unknown kernel checks\n");
	printf("  -m         build a policy module instead of a base module\n");
	printf("  -M         enable MLS policy\n");
	printf("  -N         do not check neverallow rules\n");
	printf("  -L         output line markers for allow rules\n");
	printf("  -o FILE    write module to FILE (else just check syntax)\n");
	printf("  -c VERSION build a policy module targeting a modular policy version (%d-%d)\n",
	       MOD_POLICYDB_VERSION_MIN, MOD_POLICYDB_VERSION_MAX);
	exit(1);
}

int main(int argc, char **argv)
{
	const char *file = txtfile, *outfile = NULL;
	unsigned int binary = 0, cil = 0, disable_neverallow = 0;
	unsigned int line_marker_for_allow = 0;
	unsigned int policy_type = POLICY_BASE;
	unsigned int policyvers = MOD_POLICYDB_VERSION_MAX;
	int ch;
	int show_version = 0;
	policydb_t modpolicydb;
	const struct option long_options[] = {
		{"help", no_argument, NULL, 'h'},
		{"output", required_argument, NULL, 'o'},
		{"binary", no_argument, NULL, 'b'},
		{"version", no_argument, NULL, 'V'},
		{"handle-unknown", required_argument, NULL, 'U'},
		{"mls", no_argument, NULL, 'M'},
		{"disable-neverallow", no_argument, NULL, 'N'},
		{"line-marker-for-allow", no_argument, NULL, 'L'},
		{"cil", no_argument, NULL, 'C'},
		{"werror", no_argument, NULL, 'E'},
		{NULL, 0, NULL, 0}
	};

	while ((ch = getopt_long(argc, argv, "ho:bVEU:mMNCc:L", long_options, NULL)) != -1) {
		switch (ch) {
		case 'h':
			usage(argv[0]);
			break;
		case 'o':
			outfile = optarg;
			break;
		case 'b':
			binary = 1;
			file = binfile;
			break;
		case 'V':
			show_version = 1;
			break;
		case 'E':
			werror = 1;
			break;
		case 'U':
			if (!strcasecmp(optarg, "deny")) {
				handle_unknown = DENY_UNKNOWN;
				break;
			}
			if (!strcasecmp(optarg, "reject")) {
				handle_unknown = REJECT_UNKNOWN;
				break;
			}
			if (!strcasecmp(optarg, "allow")) {
				handle_unknown = ALLOW_UNKNOWN;
				break;
			}
			usage(argv[0]);
		case 'm':
			policy_type = POLICY_MOD;
			break;
		case 'M':
			mlspol = 1;
			break;
		case 'N':
			disable_neverallow = 1;
			break;
		case 'C':
			cil = 1;
			break;
		case 'c': {
			long int n;
			errno = 0;
			n = strtol(optarg, NULL, 10);
			if (errno) {
				fprintf(stderr,
					"Invalid policyvers specified: %s\n",
					optarg);
				usage(argv[0]);
			}

			if (n < MOD_POLICYDB_VERSION_MIN
			    || n > MOD_POLICYDB_VERSION_MAX) {
				fprintf(stderr,
					"policyvers value %ld not in range %d-%d\n",
					n, MOD_POLICYDB_VERSION_MIN,
					MOD_POLICYDB_VERSION_MAX);
				usage(argv[0]);
			}

			policyvers = n;
			break;
		}
		case 'L':
			line_marker_for_allow = 1;
			break;
		default:
			usage(argv[0]);
		}
	}

	if (show_version) {
		printf("Module versions %d-%d\n",
		       MOD_POLICYDB_VERSION_MIN, MOD_POLICYDB_VERSION_MAX);
		exit(0);
	}

	if (handle_unknown && (policy_type != POLICY_BASE)) {
		fprintf(stderr, "%s:  Handling of unknown classes and permissions is only valid in the base module.\n", argv[0]);
		exit(1);
	}

	if (binary && (policy_type != POLICY_BASE)) {
		fprintf(stderr, "%s:  -b and -m are incompatible with each other.\n", argv[0]);
		exit(1);
	}

	if (line_marker_for_allow && !cil) {
		fprintf(stderr, "%s:  -L must be used along with -C.\n", argv[0]);
		exit(1);
	}

	if (optind != argc) {
		file = argv[optind++];
		if (optind != argc)
			usage(argv[0]);
	}

	/* Set policydb and sidtab used by libsepol service functions
	   to my structures, so that I can directly populate and
	   manipulate them. */
	sepol_set_policydb(&modpolicydb);
	sepol_set_sidtab(&sidtab);

	if (binary) {
		if (read_binary_policy(&modpolicydb, file, argv[0]) == -1) {
			exit(1);
		}
	} else {
		if (policydb_init(&modpolicydb)) {
			fprintf(stderr, "%s: out of memory!\n", argv[0]);
			exit(1);
		}

		modpolicydb.policy_type = policy_type;
		modpolicydb.mls = mlspol;
		modpolicydb.handle_unknown = handle_unknown;
		modpolicydb.policyvers = policyvers;

		if (read_source_policy(&modpolicydb, file, argv[0]) == -1) {
			exit(1);
		}

		if (hierarchy_check_constraints(NULL, &modpolicydb)) {
			exit(1);
		}
	}

	if (policy_type != POLICY_BASE && outfile) {
		char *out_name;
		char *separator;
		char *mod_name = modpolicydb.name;
		char *out_path = strdup(outfile);
		if (out_path == NULL) {
			fprintf(stderr, "%s:  out of memory\n", argv[0]);
			exit(1);
		}
		out_name = basename(out_path);
		separator = strrchr(out_name, '.');
		if (separator) {
			*separator = '\0';
		}
		if (strcmp(mod_name, out_name) != 0) {
			fprintf(stderr,	"%s:  Module name %s is different than the output base filename %s\n", argv[0], mod_name, out_name);
			exit(1);
		}
		free(out_path);
	}

	if (modpolicydb.policy_type == POLICY_BASE && !cil) {
		/* Verify that we can successfully expand the base module. */
		policydb_t kernpolicydb;

		if (policydb_init(&kernpolicydb)) {
			fprintf(stderr, "%s:  policydb_init failed\n", argv[0]);
			exit(1);
		}
		if (link_modules(NULL, &modpolicydb, NULL, 0, 0)) {
			fprintf(stderr, "%s:  link modules failed\n", argv[0]);
			exit(1);
		}
		if (expand_module(NULL, &modpolicydb, &kernpolicydb, /*verbose=*/0, !disable_neverallow)) {
			fprintf(stderr, "%s:  expand module failed\n", argv[0]);
			exit(1);
		}
		policydb_destroy(&kernpolicydb);
	}

	if (policydb_load_isids(&modpolicydb, &sidtab))
		exit(1);

	sepol_sidtab_destroy(&sidtab);

	if (outfile) {
		FILE *outfp = fopen(outfile, "w");

		if (!outfp) {
			fprintf(stderr, "%s:  error opening %s:  %s\n", argv[0], outfile, strerror(errno));
			exit(1);
		}

		if (!cil) {
			if (write_binary_policy(&modpolicydb, outfp, policy_type, policyvers) != 0) {
				fprintf(stderr, "%s:  error writing %s\n", argv[0], outfile);
				exit(1);
			}
		} else {
			if (line_marker_for_allow) {
				modpolicydb.line_marker_avrules |= AVRULE_ALLOWED | AVRULE_XPERMS_ALLOWED;
			}
			if (sepol_module_policydb_to_cil(outfp, &modpolicydb, 0) != 0) {
				fprintf(stderr, "%s:  error writing %s\n", argv[0], outfile);
				exit(1);
			}
		}

		if (fclose(outfp)) {
			fprintf(stderr, "%s:  error closing %s:  %s\n", argv[0], outfile, strerror(errno));
			exit(1);
		}
	} else if (cil) {
		fprintf(stderr, "%s:  No file to write CIL was specified\n", argv[0]);
		exit(1);
	}

	policydb_destroy(&modpolicydb);

	return 0;
}

/* FLASK */
