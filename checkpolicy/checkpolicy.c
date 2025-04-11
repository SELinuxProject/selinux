
/*
 * Author : Stephen Smalley, <stephen.smalley.work@gmail.com>
 */

/*
 * Updated: Trusted Computer Solutions, Inc. <dgoeddel@trustedcs.com>
 *
 *	Support for enhanced MLS infrastructure.
 *
 * Updated: Karl MacMillan <kmacmillan@tresys.com>
 *
 * 	Added conditional policy language extensions
 *
 * Updated: James Morris <jmorris@intercode.com.au>
 *
 *	Added IPv6 support.
 *
 * Updated: Joshua Brindle <jbrindle@tresys.com>
 *	    Karl MacMillan <kmacmillan@tresys.com>
 *          Jason Tang     <jtang@tresys.com>
 *
 *	Policy Module support.
 *
 * Copyright (C) 2017 Mellanox Technologies Inc.
 * Copyright (C) 2004-2005 Trusted Computer Solutions, Inc.
 * Copyright (C) 2003 - 2005 Tresys Technology, LLC
 * Copyright (C) 2003 Red Hat, Inc., James Morris <jmorris@redhat.com>
 *	This program is free software; you can redistribute it and/or modify
 *  	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, version 2.
 */

/* FLASK */

/* 
 * checkpolicy
 *
 * Load and check a policy configuration.
 *
 * A policy configuration is created in a text format,
 * and then compiled into a binary format for use by
 * the security server.  By default, checkpolicy reads
 * the text format.   If '-b' is specified, then checkpolicy
 * reads the binary format instead.
 * 
 * If '-o output_file' is specified, then checkpolicy 
 * writes the binary format version of the configuration
 * to the specified output file.  
 * 
 * If '-d' is specified, then checkpolicy permits the user 
 * to interactively test the security server functions with 
 * the loaded policy configuration.
 *
 * If '-c' is specified, then the supplied parameter is used to
 * determine which policy version to use for generating binary
 * policy.  This is for compatibility with older kernels. If any
 * booleans or conditional rules are thrown away a warning is printed.
 */

#include <ctype.h>
#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#ifndef IPPROTO_DCCP
#define IPPROTO_DCCP 33
#endif
#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <sys/mman.h>

#include <sepol/module_to_cil.h>
#include <sepol/kernel_to_cil.h>
#include <sepol/kernel_to_conf.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/services.h>
#include <sepol/policydb/conditional.h>
#include <sepol/policydb/hierarchy.h>
#include <sepol/policydb/expand.h>
#include <sepol/policydb/link.h>

#include "queue.h"
#include "parse_util.h"

static policydb_t policydb;
static sidtab_t sidtab;

extern policydb_t *policydbp;
extern int mlspol;
extern int werror;

static int handle_unknown = SEPOL_DENY_UNKNOWN;
static const char *txtfile = "policy.conf";
static const char *binfile = "policy";

static __attribute__((__noreturn__)) void usage(const char *progname)
{
	printf
	    ("usage:  %s [-b[F]] [-C] [-d] [-U handle_unknown (allow,deny,reject)] [-M] "
	     "[-N] [-c policyvers (%d-%d)] [-o output_file|-] [-S] [-O] "
	     "[-t target_platform (selinux,xen)] [-E] [-V] [-L] [input_file]\n",
	     progname, POLICYDB_VERSION_MIN, POLICYDB_VERSION_MAX);
	exit(1);
}

#define FGETS(out, size, in) \
do { \
	if (fgets(out,size,in)==NULL) {	\
		fprintf(stderr, "fgets failed at line %d: %s\n", __LINE__, \
			strerror(errno)); \
		exit(1);\
	} \
} while (0)

static int print_sid(sepol_security_id_t sid,
		     context_struct_t * context
		     __attribute__ ((unused)), void *data
		     __attribute__ ((unused)))
{
	sepol_security_context_t scontext;
	size_t scontext_len;
	int rc;

	rc = sepol_sid_to_context(sid, &scontext, &scontext_len);
	if (rc)
		printf("sid %d -> error %d\n", sid, rc);
	else {
		printf("sid %d -> scontext %s\n", sid, scontext);
		free(scontext);
	}
	return 0;
}

struct val_to_name {
	unsigned int val;
	char *name;
};

static int find_perm(hashtab_key_t key, hashtab_datum_t datum, void *p)
{
	struct val_to_name *v = p;
	perm_datum_t *perdatum;

	perdatum = (perm_datum_t *) datum;

	if (v->val == perdatum->s.value) {
		v->name = key;
		return 1;
	}

	return 0;
}

#ifdef EQUIVTYPES
static int insert_type_rule(avtab_key_t * k, avtab_datum_t * d,
			    struct avtab_node *type_rules)
{
	struct avtab_node *p, *c, *n;

	for (p = type_rules, c = type_rules->next; c; p = c, c = c->next) {
		/* 
		 * Find the insertion point, keeping the list
		 * ordered by source type, then target type, then
		 * target class.
		 */
		if (k->source_type < c->key.source_type)
			break;
		if (k->source_type == c->key.source_type &&
		    k->target_type < c->key.target_type)
			break;
		if (k->source_type == c->key.source_type &&
		    k->target_type == c->key.target_type &&
		    k->target_class < c->key.target_class)
			break;
	}

	/* Insert the rule */
	n = malloc(sizeof(struct avtab_node));
	if (!n) {
		fprintf(stderr, "out of memory\n");
		exit(1);
	}

	n->key = *k;
	n->datum = *d;
	n->next = p->next;
	p->next = n;
	return 0;
}

static int create_type_rules(avtab_key_t * k, avtab_datum_t * d, void *args)
{
	struct avtab_node *type_rules = args;

	if (d->specified & AVTAB_ALLOWED) {
		/* 
		 * Insert the rule into the lists for both 
		 * the source type and the target type.
		 */
		if (insert_type_rule(k, d, &type_rules[k->source_type - 1]))
			return -1;
		if (insert_type_rule(k, d, &type_rules[k->target_type - 1]))
			return -1;
	}

	return 0;
}

static void free_type_rules(struct avtab_node *l)
{
	struct avtab_node *tmp;

	while (l) {
		tmp = l;
		l = l->next;
		free(tmp);
	}
}

static int identify_equiv_types(void)
{
	struct avtab_node *type_rules, *l1, *l2;
	int i, j;

	/*
	 * Create a list of access vector rules for each type
	 * from the access vector table.
	 */
	type_rules = malloc(sizeof(struct avtab_node) * policydb.p_types.nprim);
	if (!type_rules) {
		fprintf(stderr, "out of memory\n");
		exit(1);
	}
	memset(type_rules, 0,
	       sizeof(struct avtab_node) * policydb.p_types.nprim);
	if (avtab_map(&policydb.te_avtab, create_type_rules, type_rules))
		exit(1);

	/*
	 * Compare the type lists and identify equivalent types.
	 */
	for (i = 0; i < policydb.p_types.nprim - 1; i++) {
		if (!type_rules[i].next)
			continue;
		for (j = i + 1; j < policydb.p_types.nprim; j++) {
			for (l1 = type_rules[i].next, l2 = type_rules[j].next;
			     l1 && l2; l1 = l1->next, l2 = l2->next) {
				if (l2->key.source_type == (j + 1)) {
					if (l1->key.source_type != (i + 1))
						break;
				} else {
					if (l1->key.source_type !=
					    l2->key.source_type)
						break;
				}
				if (l2->key.target_type == (j + 1)) {
					if (l1->key.target_type != (i + 1))
						break;
				} else {
					if (l1->key.target_type !=
					    l2->key.target_type)
						break;
				}
				if (l1->key.target_class != l2->key.target_class
				    || l1->datum.allowed != l2->datum.allowed)
					break;
			}
			if (l1 || l2)
				continue;
			free_type_rules(type_rules[j].next);
			type_rules[j].next = NULL;
			printf("Types %s and %s are equivalent.\n",
			       policydb.p_type_val_to_name[i],
			       policydb.p_type_val_to_name[j]);
		}
		free_type_rules(type_rules[i].next);
		type_rules[i].next = NULL;
	}

	free(type_rules);
	return 0;
}
#endif

static int display_bools(void)
{
	uint32_t i;

	for (i = 0; i < policydbp->p_bools.nprim; i++) {
		printf("%s : %d\n", policydbp->p_bool_val_to_name[i],
		       policydbp->bool_val_to_struct[i]->state);
	}
	return 0;
}

static void display_expr(const cond_expr_t * exp)
{

	const cond_expr_t *cur;
	for (cur = exp; cur != NULL; cur = cur->next) {
		switch (cur->expr_type) {
		case COND_BOOL:
			printf("%s ",
			       policydbp->p_bool_val_to_name[cur->boolean - 1]);
			break;
		case COND_NOT:
			printf("! ");
			break;
		case COND_OR:
			printf("|| ");
			break;
		case COND_AND:
			printf("&& ");
			break;
		case COND_XOR:
			printf("^ ");
			break;
		case COND_EQ:
			printf("== ");
			break;
		case COND_NEQ:
			printf("!= ");
			break;
		default:
			printf("error!");
			break;
		}
	}
}

static int display_cond_expressions(void)
{
	const cond_node_t *cur;

	for (cur = policydbp->cond_list; cur != NULL; cur = cur->next) {
		printf("expression: ");
		display_expr(cur->expr);
		printf("current state: %d\n", cur->cur_state);
	}
	return 0;
}

static int change_bool(const char *name, int state)
{
	cond_bool_datum_t *boolean;

	boolean = hashtab_search(policydbp->p_bools.table, name);
	if (boolean == NULL) {
		printf("Could not find bool %s\n", name);
		return -1;
	}
	boolean->state = state;
	evaluate_conds(policydbp);
	return 0;
}

static int check_level(hashtab_key_t key, hashtab_datum_t datum, void *arg __attribute__ ((unused)))
{
	level_datum_t *levdatum = (level_datum_t *) datum;

	if (!levdatum->isalias && levdatum->notdefined) {
		fprintf(stderr, "Error:  sensitivity %s was not used in a level definition!\n",
				key);
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	policydb_t parse_policy;
	sepol_security_class_t tclass;
	sepol_security_id_t ssid, tsid, *sids, oldsid, newsid, tasksid;
	sepol_security_context_t scontext;
	struct sepol_av_decision avd;
	class_datum_t *cladatum;
	const char *file = txtfile;
	char ans[80 + 1], *path, *fstype;
	const char *outfile = NULL;
	size_t scontext_len, pathlen;
	unsigned int i;
	unsigned int protocol, port;
	unsigned int binary = 0, debug = 0, sort = 0, cil = 0, conf = 0, optimize = 0, disable_neverallow = 0;
	unsigned int line_marker_for_allow = 0;
	struct val_to_name v;
	int ret, ch, fd, target = SEPOL_TARGET_SELINUX;
	unsigned int policyvers = 0;
	unsigned int nel, uret;
	struct stat sb;
	void *map;
	FILE *outfp = NULL;
	char *name;
	int state;
	int show_version = 0;
	char *reason_buf = NULL;
	unsigned int reason;
	int flags;
	struct policy_file pf;
	const struct option long_options[] = {
		{"output", required_argument, NULL, 'o'},
		{"target", required_argument, NULL, 't'},
		{"binary", no_argument, NULL, 'b'},
		{"debug", no_argument, NULL, 'd'},
		{"version", no_argument, NULL, 'V'},
		{"handle-unknown", required_argument, NULL, 'U'},
		{"mls", no_argument, NULL, 'M'},
		{"disable-neverallow", no_argument, NULL, 'N'},
		{"cil", no_argument, NULL, 'C'},
		{"conf",no_argument, NULL, 'F'},
		{"sort", no_argument, NULL, 'S'},
		{"optimize", no_argument, NULL, 'O'},
		{"werror", no_argument, NULL, 'E'},
		{"line-marker-for-allow", no_argument, NULL, 'L'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	while ((ch = getopt_long(argc, argv, "o:t:dbU:MNCFSVc:OELh", long_options, NULL)) != -1) {
		switch (ch) {
		case 'o':
			outfile = optarg;
			break;
		case 't':
			if (!strcasecmp(optarg, "Xen"))
				target = SEPOL_TARGET_XEN;
			else if (!strcasecmp(optarg, "SELinux"))
				target = SEPOL_TARGET_SELINUX;
			else{
				fprintf(stderr, "%s:  Unknown target platform:"
					"%s\n", argv[0], optarg);
				exit(1);
			}
			break;
		case 'b':
			binary = 1;
			file = binfile;
			break;
		case 'd':
			debug = 1;
			break;
		case 'V':
			show_version = 1;
			break;
		case 'U':
			if (!strcasecmp(optarg, "deny")) {
				handle_unknown = DENY_UNKNOWN;
				break;
			}
			if (!strcasecmp(optarg, "allow")) {
				handle_unknown = ALLOW_UNKNOWN;
				break;
			}
			if (!strcasecmp(optarg, "reject")) {
				handle_unknown = REJECT_UNKNOWN;
				break;
			}
			usage(argv[0]);
		case 'S':
			sort = 1;
			break;
		case 'O':
			optimize = 1;
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
		case 'F':
			conf = 1;
			break;
		case 'c':{
				long int n;
				errno = 0;
				n = strtol(optarg, NULL, 10);
				if (errno) {
					fprintf(stderr,
						"Invalid policyvers specified: %s\n",
						optarg);
					usage(argv[0]);
					exit(1);
				}
				if (n < POLICYDB_VERSION_MIN
				    || n > POLICYDB_VERSION_MAX) {
					fprintf(stderr,
						"policyvers value %ld not in range %d-%d\n",
						n, POLICYDB_VERSION_MIN,
						POLICYDB_VERSION_MAX);
					usage(argv[0]);
					exit(1);
				}
				policyvers = n;
				break;
			}
		case 'E':
			 werror = 1;
			 break;
		case 'L':
			line_marker_for_allow = 1;
			break;
		case 'h':
		default:
			usage(argv[0]);
		}
	}

	if (show_version) {
		printf("%d (compatibility range %d-%d)\n",
			   policyvers ? policyvers : POLICYDB_VERSION_MAX ,
		       POLICYDB_VERSION_MAX, POLICYDB_VERSION_MIN);
		exit(0);
	}

	if (optind != argc) {
		file = argv[optind++];
		if (optind != argc)
			usage(argv[0]);
	}
	/* Set policydb and sidtab used by libsepol service functions
	   to my structures, so that I can directly populate and
	   manipulate them. */
	sepol_set_policydb(&policydb);
	sepol_set_sidtab(&sidtab);

	if (cil && conf) {
		fprintf(stderr, "Can't convert to CIL and policy.conf at the same time\n");
		exit(1);
	}

	if (line_marker_for_allow && !cil) {
		fprintf(stderr, "Must convert to CIL for line markers to be printed\n");
		exit(1);
	}

	if (binary) {
		fd = open(file, O_RDONLY);
		if (fd < 0) {
			fprintf(stderr, "Can't open '%s':  %s\n",
				file, strerror(errno));
			exit(1);
		}
		if (fstat(fd, &sb) < 0) {
			fprintf(stderr, "Can't stat '%s':  %s\n",
				file, strerror(errno));
			exit(1);
		}
		map =
		    mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE,
			 fd, 0);
		if (map == MAP_FAILED) {
			fprintf(stderr, "Can't map '%s':  %s\n",
				file, strerror(errno));
			exit(1);
		}
		policy_file_init(&pf);
		pf.type = PF_USE_MEMORY;
		pf.data = map;
		pf.len = sb.st_size;
		if (policydb_init(&policydb)) {
			fprintf(stderr, "%s:  policydb_init:  Out of memory!\n",
				argv[0]);
			exit(1);
		}
		ret = policydb_read(&policydb, &pf, 1);
		if (ret) {
			fprintf(stderr,
				"%s:  error(s) encountered while parsing configuration\n",
				argv[0]);
			exit(1);
		}
		policydbp = &policydb;

		/* Check Policy Consistency */
		if (policydbp->mls) {
			if (!mlspol) {
				fprintf(stderr, "%s:  MLS policy, but non-MLS"
					" is specified\n", argv[0]);
				exit(1);
			}
		} else {
			if (mlspol) {
				fprintf(stderr, "%s:  non-MLS policy, but MLS"
					" is specified\n", argv[0]);
				exit(1);
			}
		}

		if (policydbp->policyvers <= POLICYDB_VERSION_PERMISSIVE) {
			if (policyvers > policydbp->policyvers) {
				fprintf(stderr, "Binary policies with version <= %u cannot be upgraded\n", POLICYDB_VERSION_PERMISSIVE);
			} else if (policyvers) {
				policydbp->policyvers = policyvers;
			}
		} else {
			policydbp->policyvers = policyvers ? policyvers : POLICYDB_VERSION_MAX;
		}
	} else {
		if (conf) {
			fprintf(stderr, "Can only generate policy.conf from binary policy\n");
			exit(1);
		}
		if (policydb_init(&parse_policy))
			exit(1);
		/* We build this as a base policy first since that is all the parser understands */
		parse_policy.policy_type = POLICY_BASE;
		policydb_set_target_platform(&parse_policy, target);

		/* Let sepol know if we are dealing with MLS support */
		parse_policy.mls = mlspol;
		parse_policy.handle_unknown = handle_unknown;
		parse_policy.policyvers = policyvers ? policyvers : POLICYDB_VERSION_MAX;

		policydbp = &parse_policy;

		if (read_source_policy(policydbp, file, "checkpolicy") < 0)
			exit(1);

		if (hashtab_map(policydbp->p_levels.table, check_level, NULL))
			exit(1);

		/* Linking takes care of optional avrule blocks */
		if (link_modules(NULL, policydbp, NULL, 0, 0)) {
			fprintf(stderr, "Error while resolving optionals\n");
			exit(1);
		}

		if (!cil) {
			if (policydb_init(&policydb)) {
				fprintf(stderr, "%s:  policydb_init failed\n", argv[0]);
				exit(1);
			}
			if (expand_module(NULL, policydbp, &policydb, /*verbose=*/0, !disable_neverallow)) {
				fprintf(stderr, "Error while expanding policy\n");
				exit(1);
			}
			policydb.policyvers = policyvers ? policyvers : POLICYDB_VERSION_MAX;
			policydb_destroy(policydbp);
			policydbp = &policydb;
		}
	}

	if (policydb_load_isids(&policydb, &sidtab))
		exit(1);

	if (optimize && policydbp->policy_type == POLICY_KERN) {
		ret = policydb_optimize(policydbp);
		if (ret) {
			fprintf(stderr, "%s:  error optimizing policy\n", argv[0]);
			exit(1);
		}
	}

	if (outfile) {
		if (!strcmp(outfile, "-")) {
			outfp = stdout;
			outfile = "<STDOUT>";
		} else {
			outfp = fopen(outfile, "w");
			if (!outfp) {
				perror(outfile);
				exit(1);
			}
		}

		if (!cil) {
			if (!conf) {
				policydb.policy_type = POLICY_KERN;

				policy_file_init(&pf);
				pf.type = PF_USE_STDIO;
				pf.fp = outfp;
				if (sort) {
					ret = policydb_sort_ocontexts(&policydb);
					if (ret) {
						fprintf(stderr, "%s:  error sorting ocontexts\n",
						argv[0]);
						exit(1);
					}
				}
				ret = policydb_write(&policydb, &pf);
			} else {
				ret = sepol_kernel_policydb_to_conf(outfp, policydbp);
			}
			if (ret) {
				fprintf(stderr, "%s:  error writing %s\n",
						argv[0], outfile);
				exit(1);
			}
		} else {
			if (line_marker_for_allow) {
				policydbp->line_marker_avrules |= AVRULE_ALLOWED | AVRULE_XPERMS_ALLOWED;
			}
			if (binary) {
				ret = sepol_kernel_policydb_to_cil(outfp, policydbp);
			} else {
				ret = sepol_module_policydb_to_cil(outfp, policydbp, 1);
			}
			if (ret) {
				fprintf(stderr, "%s:  error writing %s\n", argv[0], outfile);
				exit(1);
			}
		}

		if (outfp != stdout) {
			if(fclose(outfp)) {
				fprintf(stderr, "%s:  error closing %s:  %s\n", argv[0], outfile, strerror(errno));
				exit(1);
			}
		}
	} else if (cil) {
		fprintf(stderr, "%s:  No file to write CIL was specified\n", argv[0]);
		exit(1);
	}

	if (!debug) {
		policydb_destroy(&policydb);
		sepol_sidtab_destroy(&sidtab);
		exit(0);
	}

      menu:
	printf("\nSelect an option:\n");
	printf("0)  Call compute_access_vector\n");
	printf("1)  Call sid_to_context\n");
	printf("2)  Call context_to_sid\n");
	printf("3)  Call transition_sid\n");
	printf("4)  Call member_sid\n");
	printf("5)  Call change_sid\n");
	printf("6)  Call list_sids\n");
	printf("7)  Call load_policy\n");
	printf("8)  Call fs_sid\n");
	printf("9)  Call port_sid\n");
	printf("a)  Call netif_sid\n");
	printf("b)  Call node_sid\n");
	printf("c)  Call fs_use\n");
	printf("d)  Call genfs_sid\n");
	printf("e)  Call get_user_sids\n");
	printf("f)  display conditional bools\n");
	printf("g)  display conditional expressions\n");
	printf("h)  change a boolean value\n");
	printf("i)  display constraint expressions\n");
	printf("j)  display validatetrans expressions\n");
	printf("k)  Call ibpkey_sid\n");
	printf("l)  Call ibendport_sid\n");
#ifdef EQUIVTYPES
	printf("z)  Show equivalent types\n");
#endif
	printf("m)  Show menu again\n");
	printf("q)  Exit\n");
	while (1) {
		printf("\nChoose:  ");
		FGETS(ans, sizeof(ans), stdin);
		switch (ans[0]) {
		case '0':
			printf("source sid?  ");
			FGETS(ans, sizeof(ans), stdin);
			ssid = atoi(ans);

			printf("target sid?  ");
			FGETS(ans, sizeof(ans), stdin);
			tsid = atoi(ans);

			printf("target class?  ");
			FGETS(ans, sizeof(ans), stdin);
			if (isdigit(ans[0])) {
				tclass = atoi(ans);
				if (!tclass
				    || tclass > policydb.p_classes.nprim) {
					printf("\nNo such class.\n");
					break;
				}
				cladatum =
				    policydb.class_val_to_struct[tclass - 1];
			} else {
				ans[strlen(ans) - 1] = 0;
				cladatum =
				    (class_datum_t *) hashtab_search(policydb.
								     p_classes.
								     table,
								     ans);
				if (!cladatum) {
					printf("\nNo such class\n");
					break;
				}
				tclass = cladatum->s.value;
			}

			if (!cladatum->comdatum && !cladatum->permissions.nprim) {
				printf
				    ("\nNo access vector definition for that class\n");
				break;
			}
			ret = sepol_compute_av(ssid, tsid, tclass, 0, &avd);
			switch (ret) {
			case 0:
				printf("\nallowed {");
				for (i = 1; i <= sizeof(avd.allowed) * 8; i++) {
					if (avd.allowed & (UINT32_C(1) << (i - 1))) {
						v.val = i;
						ret =
						    hashtab_map(cladatum->
								permissions.
								table,
								find_perm, &v);
						if (!ret && cladatum->comdatum) {
							ret =
							    hashtab_map
							    (cladatum->
							     comdatum->
							     permissions.table,
							     find_perm, &v);
						}
						if (ret)
							printf(" %s", v.name);
					}
				}
				printf(" }\n");
				break;
			case -EINVAL:
				printf("\ninvalid sid\n");
				break;
			default:
				printf("return code 0x%x\n", ret);
			}
			break;
		case '1':
			printf("sid?  ");
			FGETS(ans, sizeof(ans), stdin);
			ssid = atoi(ans);
			ret = sepol_sid_to_context(ssid,
						   &scontext, &scontext_len);
			switch (ret) {
			case 0:
				printf("\nscontext %s\n", scontext);
				free(scontext);
				break;
			case -EINVAL:
				printf("\ninvalid sid\n");
				break;
			case -ENOMEM:
				printf("\nout of memory\n");
				break;
			default:
				printf("return code 0x%x\n", ret);
			}
			break;
		case '2':
			printf("scontext?  ");
			FGETS(ans, sizeof(ans), stdin);
			scontext_len = strlen(ans);
			ans[scontext_len - 1] = 0;
			ret = sepol_context_to_sid(ans, scontext_len, &ssid);
			switch (ret) {
			case 0:
				printf("\nsid %d\n", ssid);
				break;
			case -EINVAL:
				printf("\ninvalid context\n");
				break;
			case -ENOMEM:
				printf("\nout of memory\n");
				break;
			default:
				printf("return code 0x%x\n", ret);
			}
			break;
		case '3':
		case '4':
		case '5':
			ch = ans[0];

			printf("source sid?  ");
			FGETS(ans, sizeof(ans), stdin);
			ssid = atoi(ans);
			printf("target sid?  ");
			FGETS(ans, sizeof(ans), stdin);
			tsid = atoi(ans);

			printf("object class?  ");
			FGETS(ans, sizeof(ans), stdin);
			if (isdigit(ans[0])) {
				tclass = atoi(ans);
				if (!tclass
				    || tclass > policydb.p_classes.nprim) {
					printf("\nNo such class.\n");
					break;
				}
			} else {
				ans[strlen(ans) - 1] = 0;
				cladatum =
				    (class_datum_t *) hashtab_search(policydb.
								     p_classes.
								     table,
								     ans);
				if (!cladatum) {
					printf("\nNo such class\n");
					break;
				}
				tclass = cladatum->s.value;
			}

			if (ch == '3')
				ret =
				    sepol_transition_sid(ssid, tsid, tclass,
							 &ssid);
			else if (ch == '4')
				ret =
				    sepol_member_sid(ssid, tsid, tclass, &ssid);
			else
				ret =
				    sepol_change_sid(ssid, tsid, tclass, &ssid);
			switch (ret) {
			case 0:
				printf("\nsid %d\n", ssid);
				break;
			case -EINVAL:
				printf("\ninvalid sid\n");
				break;
			case -ENOMEM:
				printf("\nout of memory\n");
				break;
			default:
				printf("return code 0x%x\n", ret);
			}
			break;
		case '6':
			sepol_sidtab_map(&sidtab, print_sid, 0);
			break;
		case '7':
			printf("pathname?  ");
			FGETS(ans, sizeof(ans), stdin);
			pathlen = strlen(ans);
			ans[pathlen - 1] = 0;
			fd = open(ans, O_RDONLY);
			if (fd < 0) {
				fprintf(stderr, "Can't open '%s':  %s\n",
					ans, strerror(errno));
				break;
			}
			if (fstat(fd, &sb) < 0) {
				fprintf(stderr, "Can't stat '%s':  %s\n",
					ans, strerror(errno));
				break;
			}
			map =
			    mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE,
				 MAP_PRIVATE, fd, 0);
			if (map == MAP_FAILED) {
				fprintf(stderr, "Can't map '%s':  %s\n",
					ans, strerror(errno));
				break;
			}
			ret = sepol_load_policy(map, sb.st_size);
			switch (ret) {
			case 0:
				printf("\nsuccess\n");
				break;
			case -EINVAL:
				printf("\ninvalid policy\n");
				break;
			case -ENOMEM:
				printf("\nout of memory\n");
				break;
			default:
				printf("return code 0x%x\n", ret);
			}
			break;
		case '8':
			printf("fs kdevname?  ");
			FGETS(ans, sizeof(ans), stdin);
			ans[strlen(ans) - 1] = 0;
			ret = sepol_fs_sid(ans, &ssid, &tsid);
			if (ret) {
				printf("unknown fs kdevname\n");
			} else {
				printf("fs_sid %d default_file_sid %d\n", ssid, tsid);
			}
			break;
		case '9':
			printf("protocol?  ");
			FGETS(ans, sizeof(ans), stdin);
			ans[strlen(ans) - 1] = 0;
			if (!strcmp(ans, "tcp") || !strcmp(ans, "TCP"))
				protocol = IPPROTO_TCP;
			else if (!strcmp(ans, "udp") || !strcmp(ans, "UDP"))
				protocol = IPPROTO_UDP;
			else if (!strcmp(ans, "dccp") || !strcmp(ans, "DCCP"))
				protocol = IPPROTO_DCCP;
			else if (!strcmp(ans, "sctp") || !strcmp(ans, "SCTP"))
				protocol = IPPROTO_SCTP;
			else {
				printf("unknown protocol\n");
				break;
			}
			printf("port? ");
			FGETS(ans, sizeof(ans), stdin);
			port = atoi(ans);
			sepol_port_sid(0, 0, protocol, port, &ssid);
			printf("sid %d\n", ssid);
			break;
		case 'a':
			printf("netif name?  ");
			FGETS(ans, sizeof(ans), stdin);
			ans[strlen(ans) - 1] = 0;
			ret = sepol_netif_sid(ans, &ssid, &tsid);
			if (ret) {
				printf("unknown name\n");
			} else {
				printf("if_sid %d default_msg_sid %d\n", ssid, tsid);
			}
			break;
		case 'b':{
				char *p;
				int family, len;
				struct in_addr addr4;
				struct in6_addr addr6;

				printf("protocol family? ");
				FGETS(ans, sizeof(ans), stdin);
				ans[strlen(ans) - 1] = 0;
				if (!strcasecmp(ans, "ipv4"))
					family = AF_INET;
				else if (!strcasecmp(ans, "ipv6"))
					family = AF_INET6;
				else {
					printf("unknown protocol family\n");
					break;
				}

				printf("node address?  ");
				FGETS(ans, sizeof(ans), stdin);
				ans[strlen(ans) - 1] = 0;

				if (family == AF_INET) {
					p = (char *)&addr4;
					len = sizeof(addr4);
				} else {
					p = (char *)&addr6;
					len = sizeof(addr6);
				}

				if (inet_pton(family, ans, p) < 1) {
					printf("error parsing address\n");
					break;
				}

				sepol_node_sid(family, p, len, &ssid);
				printf("sid %d\n", ssid);
				break;
			}
		case 'c':
			printf("fstype?  ");
			FGETS(ans, sizeof(ans), stdin);
			ans[strlen(ans) - 1] = 0;
			sepol_fs_use(ans, &uret, &ssid);
			switch (uret) {
			case SECURITY_FS_USE_XATTR:
				printf("use xattr\n");
				break;
			case SECURITY_FS_USE_TRANS:
				printf("use transition SIDs\n");
				break;
			case SECURITY_FS_USE_TASK:
				printf("use task SIDs\n");
				break;
			case SECURITY_FS_USE_GENFS:
				printf("use genfs\n");
				break;
			case SECURITY_FS_USE_NONE:
				printf("no labeling support\n");
				break;
			}
			printf("sid %d\n", ssid);
			break;
		case 'd':
			printf("fstype?  ");
			FGETS(ans, sizeof(ans), stdin);
			ans[strlen(ans) - 1] = 0;
			fstype = strdup(ans);
			printf("path?  ");
			FGETS(ans, sizeof(ans), stdin);
			ans[strlen(ans) - 1] = 0;
			path = strdup(ans);
			printf("object class?  ");
			FGETS(ans, sizeof(ans), stdin);
			if (isdigit(ans[0])) {
				tclass = atoi(ans);
				if (!tclass
				    || tclass > policydb.p_classes.nprim) {
					printf("\nNo such class.\n");
					break;
				}
			} else {
				ans[strlen(ans) - 1] = 0;
				cladatum =
				    (class_datum_t *) hashtab_search(policydb.
								     p_classes.
								     table,
								     ans);
				if (!cladatum) {
					printf("\nNo such class\n");
					break;
				}
				tclass = cladatum->s.value;
			}
			sepol_genfs_sid(fstype, path, tclass, &ssid);
			printf("sid %d\n", ssid);
			free(fstype);
			free(path);
			break;
		case 'e':
			printf("from SID?  ");
			FGETS(ans, sizeof(ans), stdin);
			ans[strlen(ans) - 1] = 0;
			ssid = atoi(ans);

			printf("username?  ");
			FGETS(ans, sizeof(ans), stdin);
			ans[strlen(ans) - 1] = 0;

			ret = sepol_get_user_sids(ssid, ans, &sids, &nel);
			switch (ret) {
			case 0:
				if (!nel)
					printf("\nnone\n");
				for (i = 0; i < nel; i++)
					print_sid(sids[i], NULL, NULL);
				free(sids);
				break;
			case -ENOMEM:
				printf("\nout of memory\n");
				break;
			case -EINVAL:
				printf("\ninvalid argument\n");
				break;
			default:
				printf("\nerror\n");
				break;
			}
			break;
		case 'f':
			display_bools();
			break;
		case 'g':
			display_cond_expressions();
			break;
		case 'h':
			printf("name? ");
			FGETS(ans, sizeof(ans), stdin);
			ans[strlen(ans) - 1] = 0;

			name = strdup(ans);
			if (name == NULL) {
				fprintf(stderr, "couldn't strdup string.\n");
				break;
			}

			printf("state? ");
			FGETS(ans, sizeof(ans), stdin);
			ans[strlen(ans) - 1] = 0;

			if (atoi(ans))
				state = 1;
			else
				state = 0;

			change_bool(name, state);
			free(name);
			break;
		case 'i':
			printf("source sid?  ");
			FGETS(ans, sizeof(ans), stdin);
			ssid = atoi(ans);

			printf("target sid?  ");
			FGETS(ans, sizeof(ans), stdin);
			tsid = atoi(ans);

			printf("target class?  ");
			FGETS(ans, sizeof(ans), stdin);
			if (isdigit(ans[0])) {
				tclass = atoi(ans);
				if (!tclass
				    || tclass > policydb.p_classes.nprim) {
					printf("\nNo such class.\n");
					break;
				}
			} else {
				ans[strlen(ans) - 1] = 0;
				cladatum =
				    (class_datum_t *) hashtab_search(policydb.
								     p_classes.
								     table,
								     ans);
				if (!cladatum) {
					printf("\nNo such class\n");
					break;
				}
				tclass = cladatum->s.value;
			}

			flags = SHOW_GRANTED;
			if (sepol_compute_av_reason_buffer(ssid, tsid,
					tclass, 0, &avd, &reason,
					&reason_buf, flags)) {
				printf("\nconstraint error\n");
				break;
			}
			if (reason_buf) {
				printf("\nConstraint expressions:\n%s",
						reason_buf);
				free(reason_buf);
			} else {
				printf("\nNo constraints found.\n");
			}
			break;
		case 'j':
			printf("old sid?  ");
			FGETS(ans, sizeof(ans), stdin);
			oldsid = atoi(ans);

			printf("new sid?  ");
			FGETS(ans, sizeof(ans), stdin);
			newsid = atoi(ans);

			printf("task sid?  ");
			FGETS(ans, sizeof(ans), stdin);
			tasksid = atoi(ans);

			printf("target class?  ");
			FGETS(ans, sizeof(ans), stdin);
			if (isdigit(ans[0])) {
				tclass = atoi(ans);
				if (!tclass
				    || tclass > policydb.p_classes.nprim) {
					printf("\nNo such class.\n");
					break;
				}
			} else {
				ans[strlen(ans) - 1] = 0;
				cladatum =
				    (class_datum_t *) hashtab_search(policydb.
								     p_classes.
								     table,
								     ans);
				if (!cladatum) {
					printf("\nNo such class\n");
					break;
				}
				tclass = cladatum->s.value;
			}

			flags = SHOW_GRANTED;
			if (sepol_validate_transition_reason_buffer(oldsid,
						newsid, tasksid, tclass,
						&reason_buf, flags)) {
				printf("\nvalidatetrans error\n");
				break;
			}
			if (reason_buf) {
				printf("\nValidatetrans expressions:\n%s",
						reason_buf);
				free(reason_buf);
			} else {
				printf(
				    "\nNo validatetrans expressions found.\n");
			}
			break;
		case 'k':
			{
				char *p;
				struct in6_addr addr6;
				uint64_t subnet_prefix;
				unsigned int pkey;

				printf("subnet prefix?  ");
				FGETS(ans, sizeof(ans), stdin);
				ans[strlen(ans) - 1] = 0;
				p = (char *)&addr6;

				if (inet_pton(AF_INET6, ans, p) < 1) {
					printf("error parsing subnet prefix\n");
					break;
				}

				memcpy(&subnet_prefix, p, sizeof(subnet_prefix));
				printf("pkey? ");
				FGETS(ans, sizeof(ans), stdin);
				pkey = atoi(ans);
				sepol_ibpkey_sid(subnet_prefix, pkey, &ssid);
				printf("sid %d\n", ssid);
			}
			break;
		case 'l':
			printf("device name (eg. mlx4_0)?  ");
			FGETS(ans, sizeof(ans), stdin);
			ans[strlen(ans) - 1] = 0;

			name = strdup(ans);
			if (!name) {
				fprintf(stderr, "couldn't strdup string.\n");
				break;
			}

			printf("port? ");
			FGETS(ans, sizeof(ans), stdin);
			port = atoi(ans);
			sepol_ibendport_sid(name, port, &ssid);
			printf("sid %d\n", ssid);
			free(name);
			break;
#ifdef EQUIVTYPES
		case 'z':
			identify_equiv_types();
			break;
#endif
		case 'm':
			goto menu;
		case 'q':
			exit(0);
			break;
		default:
			printf("\nUnknown option %s.\n", ans);
		}
	}

	return 0;
}

/* FLASK */
