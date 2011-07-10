/* Authors: Frank Mayer <mayerf@tresys.com>
 *   and Karl MacMillan <kmacmillan@tresys.com>
 *
 * Copyright (C) 2003,2010 Tresys Technology, LLC
 *
 *	This program is free software; you can redistribute it and/or
 *  	modify it under the terms of the GNU General Public License as
 *  	published by the Free Software Foundation, version 2.
 *
 * Adapted from dispol.c.
 *
 * This program is used by sepolgen-ifgen to get the access for all of
 * the attributes in the policy so that it can resolve the
 * typeattribute statements in the interfaces.
 *
 * It outputs the attribute access in a similar format to what sepolgen
 * uses to store interface vectors:
 *   [Attribute sandbox_x_domain]
 *   sandbox_x_domain,samba_var_t,file,ioctl,read,getattr,lock,open
 *   sandbox_x_domain,samba_var_t,dir,getattr,search,open
 *   sandbox_x_domain,initrc_var_run_t,file,ioctl,read,getattr,lock,open
 *
 */

#include <sepol/policydb/policydb.h>
#include <sepol/policydb/avtab.h>
#include <sepol/policydb/util.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

struct val_to_name {
	unsigned int val;
	char *name;
};

static int perm_name(hashtab_key_t key, hashtab_datum_t datum, void *data)
{
	struct val_to_name *v = data;
	perm_datum_t *perdatum;

	perdatum = (perm_datum_t *) datum;

	if (v->val == perdatum->s.value) {
		v->name = key;
		return 1;
	}

	return 0;
}

int render_access_mask(uint32_t av, avtab_key_t *key, policydb_t *policydbp,
		       FILE *fp)
{
	struct val_to_name v;
	class_datum_t *cladatum;
	char *perm = NULL;
	unsigned int i;
	int rc;
	uint32_t tclass = key->target_class;

	cladatum = policydbp->class_val_to_struct[tclass - 1];
	for (i = 0; i < cladatum->permissions.nprim; i++) {
		if (av & (1 << i)) {
			v.val = i + 1;
			rc = hashtab_map(cladatum->permissions.table,
					 perm_name, &v);
			if (!rc && cladatum->comdatum) {
				rc = hashtab_map(cladatum->comdatum->
						 permissions.table, perm_name,
						 &v);
			}
			if (rc)
				perm = v.name;
			if (perm) {
				fprintf(fp, ",%s", perm);
			}
		}
	}

	return 0;
}

static int render_key(avtab_key_t *key, policydb_t *p, FILE *fp)
{
	char *stype, *ttype, *tclass;
	stype = p->p_type_val_to_name[key->source_type - 1];
	ttype = p->p_type_val_to_name[key->target_type - 1];
	tclass = p->p_class_val_to_name[key->target_class - 1];
	if (stype && ttype) {
		fprintf(fp, "%s,%s,%s", stype, ttype, tclass);
	} else {
		fprintf(stderr, "error rendering key\n");
		exit(1);
	}

	return 0;
}

struct callback_data
{
	uint32_t attr;
	policydb_t *policy;
	FILE *fp;
};

int output_avrule(avtab_key_t *key, avtab_datum_t *datum, void *args)
{
	struct callback_data *cb_data = (struct callback_data *)args;

	if (key->source_type != cb_data->attr)
		return 0;

	if (!(key->specified & AVTAB_AV && key->specified & AVTAB_ALLOWED))
		return 0;

	render_key(key, cb_data->policy, cb_data->fp);
	render_access_mask(datum->data, key, cb_data->policy, cb_data->fp);
	fprintf(cb_data->fp, "\n");

	return 0;
}

static int attribute_callback(hashtab_key_t key, hashtab_datum_t datum, void *datap)
{
	struct callback_data *cb_data = (struct callback_data *)datap;
	type_datum_t *t = (type_datum_t *)datum;

	if (t->flavor == TYPE_ATTRIB) {
		fprintf(cb_data->fp, "[Attribute %s]\n", key);
		cb_data->attr = t->s.value;
		if (avtab_map(&cb_data->policy->te_avtab, output_avrule, cb_data) < 0)
			return -1;
		if (avtab_map(&cb_data->policy->te_cond_avtab, output_avrule, cb_data) < 0)
			return -1;
	}

	return 0;
}

static policydb_t *load_policy(const char *filename)
{
	policydb_t *policydb;
	struct policy_file pf;
	FILE *fp;
	int ret;

	fp = fopen(filename, "r");
	if (fp == NULL) {
		fprintf(stderr, "Can't open '%s':  %s\n",
			filename, strerror(errno));
		return NULL;
	}

	policy_file_init(&pf);
	pf.type = PF_USE_STDIO;
	pf.fp = fp;

	policydb = malloc(sizeof(policydb_t));
	if (policydb == NULL) {
		fprintf(stderr, "Out of memory!\n");
		return NULL;
	}

	if (policydb_init(policydb)) {
		fprintf(stderr, "Out of memory!\n");
		free(policydb);
		return NULL;
	}

	ret = policydb_read(policydb, &pf, 1);
	if (ret) {
		fprintf(stderr,
			"error(s) encountered while parsing configuration\n");
		free(policydb);
		return NULL;
	}

	fclose(fp);

	return policydb;

}

void usage(char *progname)
{
	printf("usage: %s policy_file out_file\n", progname);
}

int main(int argc, char **argv)
{
	policydb_t *p;
	struct callback_data cb_data;
	FILE *fp;

	if (argc != 3) {
		usage(argv[0]);
		return -1;
	}

	/* Open the policy. */
	p = load_policy(argv[1]);
	if (p == NULL)
		return -1;

	/* Open the output policy. */
	fp = fopen(argv[2], "w");
	if (fp == NULL) {
		fprintf(stderr, "error opening output file\n");
		policydb_destroy(p);
		free(p);
		return -1;
	}

	/* Find all of the attributes and output their access. */
	cb_data.policy = p;
	cb_data.fp = fp;

	if (hashtab_map(p->p_types.table, attribute_callback, &cb_data)) {
		printf("error finding attributes\n");
	}

	policydb_destroy(p);
	free(p);
	fclose(fp);

	return 0;
}
