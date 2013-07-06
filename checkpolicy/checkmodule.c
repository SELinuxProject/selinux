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

#include <sepol/policydb/policydb.h>
#include <sepol/policydb/services.h>
#include <sepol/policydb/conditional.h>
#include <sepol/policydb/flask.h>
#include <sepol/policydb/hierarchy.h>
#include <sepol/policydb/expand.h>
#include <sepol/policydb/link.h>
#include <sepol/policydb/sidtab.h>

#include "queue.h"
#include "checkpolicy.h"
#include "parse_util.h"

extern char *optarg;
extern int optind;

static sidtab_t sidtab;

extern int mlspol;

static int handle_unknown = SEPOL_DENY_UNKNOWN;
static char *txtfile = "policy.conf";
static char *binfile = "policy";

unsigned int policy_type = POLICY_BASE;
unsigned int policyvers = MOD_POLICYDB_VERSION_MAX;

static int read_binary_policy(policydb_t * p, char *file, char *progname)
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

static int write_binary_policy(policydb_t * p, char *file, char *progname)
{
	FILE *outfp = NULL;
	struct policy_file pf;
	int ret;

	printf("%s:  writing binary representation (version %d) to %s\n",
	       progname, policyvers, file);

	outfp = fopen(file, "w");
	if (!outfp) {
		perror(file);
		exit(1);
	}

	p->policy_type = policy_type;
	p->policyvers = policyvers;
	p->handle_unknown = handle_unknown;

	policy_file_init(&pf);
	pf.type = PF_USE_STDIO;
	pf.fp = outfp;
	ret = policydb_write(p, &pf);
	if (ret) {
		fprintf(stderr, "%s:  error writing %s\n", progname, file);
		return -1;
	}
	fclose(outfp);
	return 0;
}

static void usage(char *progname)
{
	printf("usage:  %s [-h] [-V] [-b] [-U handle_unknown] [-m] [-M] [-o FILE] [INPUT]\n", progname);
	printf("Build base and policy modules.\n");
	printf("Options:\n");
	printf("  INPUT      build module from INPUT (else read from \"%s\")\n",
	       txtfile);
	printf("  -V         show policy versions created by this program\n");
	printf("  -b         treat input as a binary policy file\n");
	printf("  -h         print usage\n");
	printf("  -U OPTION  How to handle unknown classes and permissions\n");
	printf("               deny: Deny unknown kernel checks\n");
	printf("               reject: Reject loading of policy with unknowns\n");
	printf("               allow: Allow unknown kernel checks\n");
	printf("  -m         build a policy module instead of a base module\n");
	printf("  -M         enable MLS policy\n");
	printf("  -o FILE    write module to FILE (else just check syntax)\n");
	exit(1);
}

int main(int argc, char **argv)
{
	char *file = txtfile, *outfile = NULL;
	unsigned int binary = 0;
	int ch;
	int show_version = 0;
	policydb_t modpolicydb;
	struct option long_options[] = {
		{"help", no_argument, NULL, 'h'},
		{"output", required_argument, NULL, 'o'},
		{"binary", no_argument, NULL, 'b'},
		{"version", no_argument, NULL, 'V'},
		{"handle-unknown", required_argument, NULL, 'U'},
		{"mls", no_argument, NULL, 'M'},
		{NULL, 0, NULL, 0}
	};

	while ((ch = getopt_long(argc, argv, "ho:bVU:mM", long_options, NULL)) != -1) {
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
			policyvers = MOD_POLICYDB_VERSION_MAX;
			break;
		case 'M':
			mlspol = 1;
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
		printf("Handling of unknown classes and permissions is only ");
		printf("valid in the base module\n");
		exit(1);
	}

	if (optind != argc) {
		file = argv[optind++];
		if (optind != argc)
			usage(argv[0]);
	}
	printf("%s:  loading policy configuration from %s\n", argv[0], file);

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
			return -1;
		}

		modpolicydb.policy_type = policy_type;
		modpolicydb.mls = mlspol;
		modpolicydb.handle_unknown = handle_unknown;

		if (read_source_policy(&modpolicydb, file, argv[0]) == -1) {
			exit(1);
		}

		if (hierarchy_check_constraints(NULL, &modpolicydb)) {
			return -1;
		}
	}

	if (modpolicydb.policy_type == POLICY_BASE) {
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
		if (expand_module(NULL, &modpolicydb, &kernpolicydb, 0, 1)) {
			fprintf(stderr, "%s:  expand module failed\n", argv[0]);
			exit(1);
		}
		policydb_destroy(&kernpolicydb);
	}

	if (policydb_load_isids(&modpolicydb, &sidtab))
		exit(1);

	sepol_sidtab_destroy(&sidtab);

	printf("%s:  policy configuration loaded\n", argv[0]);

	if (outfile &&
	    write_binary_policy(&modpolicydb, outfile, argv[0]) == -1) {
		exit(1);
	}
	policydb_destroy(&modpolicydb);

	return 0;
}

/* FLASK */
