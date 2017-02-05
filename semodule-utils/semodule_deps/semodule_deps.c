/* Authors: Karl MacMillan <kmacmillan@mentalrootkit.com>
 *
 * Copyright (C) 2006 Tresys Technology, LLC
 * Copyright (C) 2006-2007 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2.
 *
 */

/* Because we _must_ muck around in the internal representation of
 * the policydb (and include the internal header below) this program
 * must be statically linked to libsepol like checkpolicy. It is
 * not clear if it is worthwhile to fix this, as exposing the details
 * of avrule_blocks - even in an ABI safe way - seems undesirable.
 */
#include <sepol/module.h>
#include <sepol/errcodes.h>
#include <sepol/policydb/policydb.h>

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
#include <assert.h>

/* for getopt */
extern char *optarg;
extern int optind;

/* This is really a horrible hack, but the base module
 * is referred to with the following name. The same
 * thing is done in the linker for displaying error
 * messages.
 */
#define BASE_NAME ((char *)"BASE")

static void usage(char *program_name)
{
	printf("usage: %s [-v -g -b] basemodpkg modpkg1 [modpkg2 ... ]\n",
	       program_name);
	exit(1);
}

/* Basic string hash and compare for the hashtables used in
 * generate_requires. Copied from symtab.c.
 */
static unsigned int reqsymhash(hashtab_t h, const_hashtab_key_t key)
{
	const char *p, *keyp;
	size_t size;
	unsigned int val;

	val = 0;
	keyp = (const char *)key;
	size = strlen(keyp);
	for (p = keyp; ((size_t) (p - keyp)) < size; p++)
		val =
		    (val << 4 | (val >> (8 * sizeof(unsigned int) - 4))) ^ (*p);
	return val & (h->size - 1);
}

static int reqsymcmp(hashtab_t h
		     __attribute__ ((unused)), const_hashtab_key_t key1,
		     const_hashtab_key_t key2)
{
	return strcmp(key1, key2);
}

/* Load a policy package from the given filename. Progname is used for
 * error reporting.
 */
static sepol_module_package_t *load_module(char *filename, char *progname)
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

/* This function generates the requirements graph and stores it in
 * a set of nested hashtables. The top level hash table stores modules
 * keyed by name. The value of that module is a hashtable storing all
 * of the requirements keyed by name. There is no value for the requirements
 * hashtable.
 *
 * This only tracks symbols that are _required_ - optional symbols
 * are completely ignored. A future version might look at this.
 *
 * This requirement generation only looks at booleans and types because:
 *  - object classes: (for now) only present in bases
 *  - roles: since they are multiply declared it is not clear how
 *           to present these requirements as they will be satisfied
 *           by multiple modules.
 *  - users: same problem as roles plus they are usually defined outside
 *           of the policy.
 *  - levels / cats: can't be required or used in modules.
 */
static hashtab_t generate_requires(policydb_t * p)
{
	avrule_block_t *block;
	avrule_decl_t *decl;
	char *mod_name, *req_name, *id;
	ebitmap_t *b;
	ebitmap_node_t *node;
	uint32_t i, j;
	int ret;
	scope_datum_t *scope;
	hashtab_t mods;
	hashtab_t reqs;

	mods = hashtab_create(reqsymhash, reqsymcmp, 64);
	if (mods == NULL)
		return NULL;

	for (block = p->global; block != NULL; block = block->next) {
		if (block->flags & AVRULE_OPTIONAL)
			continue;
		for (decl = block->branch_list; decl != NULL; decl = decl->next) {
			mod_name =
			    decl->module_name ? decl->module_name : BASE_NAME;
			for (i = 0; i < SYM_NUM; i++) {
				if (!(i == SYM_TYPES || i == SYM_BOOLS))
					continue;
				b = &decl->required.scope[i];
				ebitmap_for_each_bit(b, node, j) {
					if (!ebitmap_node_get_bit(node, j))
						continue;
					id = p->sym_val_to_name[i][j];
					scope =
					    (scope_datum_t *) hashtab_search(p->
									     scope
									     [i].
									     table,
									     id);
					/* since this is only called after a successful link,
					 * this should never happen */
					assert(scope->scope == SCOPE_DECL);
					req_name =
					    p->decl_val_to_struct[scope->
								  decl_ids[0]]->
					    module_name ? p->
					    decl_val_to_struct[scope->
							       decl_ids[0]]->
					    module_name : BASE_NAME;

					reqs =
					    (hashtab_t) hashtab_search(mods,
								       mod_name);
					if (!reqs) {
						reqs =
						    hashtab_create(reqsymhash,
								   reqsymcmp,
								   64);
						if (reqs == NULL) {
							return NULL;
						}
						ret =
						    hashtab_insert(mods,
								   mod_name,
								   reqs);
						if (ret != SEPOL_OK)
							return NULL;
					}
					ret =
					    hashtab_insert(reqs, req_name,
							   NULL);
					if (!
					    (ret == SEPOL_EEXIST
					     || ret == SEPOL_OK))
						return NULL;
				}
			}

		}
	}

	return mods;
}

static void free_requires(hashtab_t req)
{
	unsigned int i;
	hashtab_ptr_t cur;

	/* We steal memory for everything stored in the hash tables
	 * from the policydb, so this only looks like it leaks.
	 */
	for (i = 0; i < req->size; i++) {
		cur = req->htable[i];
		while (cur != NULL) {
			hashtab_destroy((hashtab_t) cur->datum);
			cur = cur->next;
		}
	}
	hashtab_destroy(req);
}

static void output_graphviz(hashtab_t mods, int exclude_base, FILE * f)
{
	unsigned int i, j;
	hashtab_ptr_t cur, cur2;
	hashtab_t reqs;

	fprintf(f, "digraph mod_deps {\n");
	fprintf(f, "\toverlap=false\n");

	for (i = 0; i < mods->size; i++) {
		cur = mods->htable[i];
		while (cur != NULL) {
			reqs = (hashtab_t) cur->datum;
			assert(reqs);
			for (j = 0; j < reqs->size; j++) {
				cur2 = reqs->htable[j];
				while (cur2 != NULL) {
					if (exclude_base
					    && strcmp(cur2->key,
						      BASE_NAME) == 0) {
						cur2 = cur2->next;
						continue;
					}
					fprintf(f, "\t%s -> %s\n", cur->key,
						cur2->key);
					cur2 = cur2->next;
				}
			}
			cur = cur->next;
		}
	}
	fprintf(f, "}\n");
}

static void output_requirements(hashtab_t mods, int exclude_base, FILE * f)
{
	unsigned int i, j;
	hashtab_ptr_t cur, cur2;
	hashtab_t reqs;
	int found_req;

	for (i = 0; i < mods->size; i++) {
		cur = mods->htable[i];
		while (cur != NULL) {
			reqs = (hashtab_t) cur->datum;
			assert(reqs);
			fprintf(f, "module: %s\n", cur->key);
			found_req = 0;
			for (j = 0; j < reqs->size; j++) {
				cur2 = reqs->htable[j];
				while (cur2 != NULL) {
					if (exclude_base
					    && strcmp(cur2->key,
						      BASE_NAME) == 0) {
						cur2 = cur2->next;
						continue;
					}
					found_req = 1;
					fprintf(f, "\t%s\n", cur2->key);
					cur2 = cur2->next;
				}
			}
			if (!found_req)
				fprintf(f, "\t[no dependencies]\n");
			cur = cur->next;
		}
	}
	fprintf(f, "}\n");
}

/* Possible commands - see the command variable in
 * main below and the man page for more info.
 */
#define SHOW_DEPS    1
#define GEN_GRAPHVIZ 2

int main(int argc, char **argv)
{
	int ch, i, num_mods;
	int verbose = 0, exclude_base = 1, command = SHOW_DEPS;
	char *basename;
	sepol_module_package_t *base, **mods;
	policydb_t *p;
	hashtab_t req;

	while ((ch = getopt(argc, argv, "vgb")) != EOF) {
		switch (ch) {
		case 'v':
			verbose = 1;
			break;
		case 'g':
			command = GEN_GRAPHVIZ;
			break;
		case 'b':
			exclude_base = 0;
			break;
		default:
			usage(argv[0]);
		}
	}

	/* check args */
	if (argc < 3 || !(optind != (argc - 1))) {
		fprintf(stderr,
			"%s:  You must provide the base module package and at least one other module package\n",
			argv[0]);
		usage(argv[0]);
	}

	basename = argv[optind++];
	base = load_module(basename, argv[0]);
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
		mods[i] = load_module(argv[optind], argv[0]);
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

	p = (policydb_t *) sepol_module_package_get_policy(base);
	if (p == NULL)
		exit(1);

	req = generate_requires(p);
	if (req == NULL)
		exit(1);

	if (command == SHOW_DEPS)
		output_requirements(req, exclude_base, stdout);
	else
		output_graphviz(req, exclude_base, stdout);

	sepol_module_package_free(base);
	for (i = 0; i < num_mods; i++)
		sepol_module_package_free(mods[i]);

	free_requires(req);

	exit(0);
}
