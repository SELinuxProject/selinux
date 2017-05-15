
/* Authors: Frank Mayer <mayerf@tresys.com> and Karl MacMillan <kmacmillan@tresys.com>
 *
 * Copyright (C) 2003,2004,2005 Tresys Technology, LLC
 *	This program is free software; you can redistribute it and/or modify
 *  	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, version 2.
 */

/* 
 * dismod.c
 *
 * Test program to the contents of a binary policy in text
 * form.
 *
 * 	dismod binary_mod_file
 */

#include <getopt.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include <sepol/policydb/policydb.h>
#include <sepol/policydb/services.h>
#include <sepol/policydb/conditional.h>
#include <sepol/policydb/flask.h>
#include <sepol/policydb/link.h>
#include <sepol/policydb/module.h>
#include <sepol/policydb/util.h>
#include <sepol/policydb/polcaps.h>

#include <byteswap.h>
#include <endian.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define le32_to_cpu(x) (x)
#else
#define le32_to_cpu(x) bswap_32(x)
#endif

#define DISPLAY_AVBLOCK_COND_AVTAB	0
#define DISPLAY_AVBLOCK_UNCOND_AVTAB	1
#define DISPLAY_AVBLOCK_ROLE_TYPE_NODE	2 /* unused? */
#define DISPLAY_AVBLOCK_ROLE_TRANS	3
#define DISPLAY_AVBLOCK_ROLE_ALLOW	4
#define DISPLAY_AVBLOCK_REQUIRES	5
#define DISPLAY_AVBLOCK_DECLARES	6
#define DISPLAY_AVBLOCK_FILENAME_TRANS	7

static policydb_t policydb;
extern unsigned int ss_initialized;

int policyvers = MOD_POLICYDB_VERSION_BASE;

static const char *symbol_labels[9] = {
	"commons",
	"classes", "roles  ", "types  ", "users  ", "bools  ",
	"levels ", "cats   ", "attribs"
};

static __attribute__((__noreturn__)) void usage(const char *progname)
{
	printf("usage:  %s binary_pol_file\n\n", progname);
	exit(1);
}

static void render_access_mask(uint32_t mask, uint32_t class, policydb_t * p,
			       FILE * fp)
{
	char *perm;
	fprintf(fp, "{");
	perm = sepol_av_to_string(p, class, mask);
	if (perm)
		fprintf(fp, "%s ", perm);
	fprintf(fp, "}");
}

static void render_access_bitmap(ebitmap_t * map, uint32_t class,
				 policydb_t * p, FILE * fp)
{
	unsigned int i;
	char *perm;
	fprintf(fp, "{");
	for (i = ebitmap_startbit(map); i < ebitmap_length(map); i++) {
		if (ebitmap_get_bit(map, i)) {
			perm = sepol_av_to_string(p, class, 1 << i);
			if (perm)
				fprintf(fp, " %s", perm);
		}
	}
	fprintf(fp, " }");
}

static void display_id(policydb_t * p, FILE * fp, uint32_t symbol_type,
		       uint32_t symbol_value, const char *prefix)
{
	char *id = p->sym_val_to_name[symbol_type][symbol_value];
	scope_datum_t *scope =
	    (scope_datum_t *) hashtab_search(p->scope[symbol_type].table, id);
	assert(scope != NULL);
	if (scope->scope == SCOPE_REQ) {
		fprintf(fp, " [%s%s]", prefix, id);
	} else {
		fprintf(fp, " %s%s", prefix, id);
	}
}

int display_type_set(type_set_t * set, uint32_t flags, policydb_t * policy,
		     FILE * fp)
{
	unsigned int i, num_types;

	if (set->flags & TYPE_STAR) {
		fprintf(fp, " * ");
		return 0;
	} else if (set->flags & TYPE_COMP) {
		fprintf(fp, " ~");
	}

	num_types = 0;
	if (flags & RULE_SELF) {
		num_types++;
	}

	for (i = ebitmap_startbit(&set->types); i < ebitmap_length(&set->types);
	     i++) {
		if (!ebitmap_get_bit(&set->types, i))
			continue;
		num_types++;
		if (num_types > 1)
			break;
	}

	if (num_types <= 1) {
		for (i = ebitmap_startbit(&set->negset);
		     i < ebitmap_length(&set->negset); i++) {
			if (!ebitmap_get_bit(&set->negset, i))
				continue;
			num_types++;
			if (num_types > 1)
				break;
		}
	}

	if (num_types > 1)
		fprintf(fp, "{");

	for (i = ebitmap_startbit(&set->types); i < ebitmap_length(&set->types);
	     i++) {
		if (!ebitmap_get_bit(&set->types, i))
			continue;
		display_id(policy, fp, SYM_TYPES, i, "");
	}

	for (i = ebitmap_startbit(&set->negset);
	     i < ebitmap_length(&set->negset); i++) {
		if (!ebitmap_get_bit(&set->negset, i))
			continue;
		display_id(policy, fp, SYM_TYPES, i, "-");
	}

	if (flags & RULE_SELF) {
		fprintf(fp, " self");
	}

	if (num_types > 1)
		fprintf(fp, " }");

	return 0;
}

int display_mod_role_set(role_set_t * roles, policydb_t * p, FILE * fp)
{
	unsigned int i, num = 0;

	if (roles->flags & ROLE_STAR) {
		fprintf(fp, " * ");
		return 0;
	} else if (roles->flags & ROLE_COMP) {
		fprintf(fp, " ~");
	}

	for (i = ebitmap_startbit(&roles->roles);
	     i < ebitmap_length(&roles->roles); i++) {
		if (!ebitmap_get_bit(&roles->roles, i))
			continue;
		num++;
		if (num > 1) {
			fprintf(fp, "{");
			break;
		}
	}

	for (i = ebitmap_startbit(&roles->roles);
	     i < ebitmap_length(&roles->roles); i++) {
		if (ebitmap_get_bit(&roles->roles, i))
			display_id(p, fp, SYM_ROLES, i, "");
	}

	if (num > 1)
		fprintf(fp, " }");

	return 0;

}

int display_avrule(avrule_t * avrule, policydb_t * policy,
		   FILE * fp)
{
	class_perm_node_t *cur;
	int num_classes;

	if (avrule == NULL) {
		fprintf(fp, "  <empty>\n");
		return 0;
	}
	if (avrule->specified & AVRULE_AV) {
		if (avrule->specified & AVRULE_ALLOWED) {
			fprintf(fp, "  allow");
		}
		if (avrule->specified & AVRULE_AUDITALLOW) {
			fprintf(fp, "  auditallow ");
		}
		if (avrule->specified & AVRULE_DONTAUDIT) {
			fprintf(fp, "  dontaudit");
		}
	} else if (avrule->specified & AVRULE_TYPE) {
		if (avrule->specified & AVRULE_TRANSITION) {
			fprintf(fp, "  type_transition");
		}
		if (avrule->specified & AVRULE_MEMBER) {
			fprintf(fp, "  type_member");
		}
		if (avrule->specified & AVRULE_CHANGE) {
			fprintf(fp, "  type_change");
		}
	} else if (avrule->specified & AVRULE_NEVERALLOW) {
		fprintf(fp, "  neverallow");
	} else if (avrule->specified & AVRULE_XPERMS) {
		if (avrule->specified & AVRULE_XPERMS_ALLOWED)
			fprintf(fp, "allowxperm ");
		else if (avrule->specified & AVRULE_XPERMS_AUDITALLOW)
			fprintf(fp, "auditallowxperm ");
		else if (avrule->specified & AVRULE_XPERMS_DONTAUDIT)
			fprintf(fp, "dontauditxperm ");
	} else {
		fprintf(fp, "     ERROR: no valid rule type specified\n");
		return -1;
	}

	if (display_type_set(&avrule->stypes, 0, policy, fp))
		return -1;

	if (display_type_set(&avrule->ttypes, avrule->flags, policy, fp))
		return -1;

	fprintf(fp, " :");
	cur = avrule->perms;
	num_classes = 0;
	while (cur) {
		num_classes++;
		if (num_classes > 1)
			break;
		cur = cur->next;
	}

	if (num_classes > 1)
		fprintf(fp, " {");

	cur = avrule->perms;
	while (cur) {
		display_id(policy, fp, SYM_CLASSES, cur->tclass - 1, "");
		cur = cur->next;
	}

	if (num_classes > 1)
		fprintf(fp, " }");
	fprintf(fp, " ");

	if (avrule->specified & (AVRULE_AV | AVRULE_NEVERALLOW)) {
		render_access_mask(avrule->perms->data, avrule->perms->tclass,
				   policy, fp);
	} else if (avrule->specified & AVRULE_TYPE) {
		display_id(policy, fp, SYM_TYPES, avrule->perms->data - 1, "");
	} else if (avrule->specified & AVRULE_XPERMS) {
		avtab_extended_perms_t xperms;
		int i;

		if (avrule->xperms->specified == AVRULE_XPERMS_IOCTLFUNCTION)
			xperms.specified = AVTAB_XPERMS_IOCTLFUNCTION;
		else if (avrule->xperms->specified == AVRULE_XPERMS_IOCTLDRIVER)
			xperms.specified = AVTAB_XPERMS_IOCTLDRIVER;
		else {
			fprintf(fp, "     ERROR: no valid xperms specified\n");
			return -1;
		}

		xperms.driver = avrule->xperms->driver;
		for (i = 0; i < EXTENDED_PERMS_LEN; i++)
			xperms.perms[i] = avrule->xperms->perms[i];

		fprintf(fp, "%s", sepol_extended_perms_to_string(&xperms));
	}

	fprintf(fp, ";\n");

	return 0;
}

int display_type_callback(hashtab_key_t key, hashtab_datum_t datum, void *data)
{
	type_datum_t *type;
	FILE *fp;
	unsigned int i, first_attrib = 1;

	type = (type_datum_t *) datum;
	fp = (FILE *) data;

	if (type->primary) {
		display_id(&policydb, fp, SYM_TYPES, type->s.value - 1, "");
		fprintf(fp, " [%d]: ", type->s.value);
	} else {
		/* as that aliases have no value of their own and that
		 * they can never be required by a module, use this
		 * alternative way of displaying a name */
		fprintf(fp, " %s [%d]: ", (char *)key, type->s.value);
	}
	if (type->flavor == TYPE_ATTRIB) {
		fprintf(fp, "attribute for types");
		for (i = ebitmap_startbit(&type->types);
		     i < ebitmap_length(&type->types); i++) {
			if (!ebitmap_get_bit(&type->types, i))
				continue;
			if (first_attrib) {
				first_attrib = 0;
			} else {
				fprintf(fp, ",");
			}
			display_id(&policydb, fp, SYM_TYPES, i, "");
		}
	} else if (type->primary) {
		fprintf(fp, "type");
	} else {
		fprintf(fp, "alias for type");
		display_id(&policydb, fp, SYM_TYPES, type->s.value - 1, "");
	}
	fprintf(fp, " flags:%x\n", type->flags);

	return 0;
}

int display_types(policydb_t * p, FILE * fp)
{
	if (hashtab_map(p->p_types.table, display_type_callback, fp))
		return -1;
	return 0;
}

int display_users(policydb_t * p, FILE * fp)
{
	unsigned int i, j;
	ebitmap_t *bitmap;
	for (i = 0; i < p->p_users.nprim; i++) {
		display_id(p, fp, SYM_USERS, i, "");
		fprintf(fp, ":");
		bitmap = &(p->user_val_to_struct[i]->roles.roles);
		for (j = ebitmap_startbit(bitmap); j < ebitmap_length(bitmap);
		     j++) {
			if (ebitmap_get_bit(bitmap, j)) {
				display_id(p, fp, SYM_ROLES, j, "");
			}
		}
		fprintf(fp, "\n");
	}
	return 0;
}

int display_bools(policydb_t * p, FILE * fp)
{
	unsigned int i;

	for (i = 0; i < p->p_bools.nprim; i++) {
		display_id(p, fp, SYM_BOOLS, i, "");
		fprintf(fp, " : %d\n", p->bool_val_to_struct[i]->state);
	}
	return 0;
}

void display_expr(policydb_t * p, cond_expr_t * exp, FILE * fp)
{

	cond_expr_t *cur;
	for (cur = exp; cur != NULL; cur = cur->next) {
		switch (cur->expr_type) {
		case COND_BOOL:
			fprintf(fp, "%s ",
				p->p_bool_val_to_name[cur->bool - 1]);
			break;
		case COND_NOT:
			fprintf(fp, "! ");
			break;
		case COND_OR:
			fprintf(fp, "|| ");
			break;
		case COND_AND:
			fprintf(fp, "&& ");
			break;
		case COND_XOR:
			fprintf(fp, "^ ");
			break;
		case COND_EQ:
			fprintf(fp, "== ");
			break;
		case COND_NEQ:
			fprintf(fp, "!= ");
			break;
		default:
			fprintf(fp, "error!");
			break;
		}
	}
}

void display_policycon(FILE * fp)
{
	/* There was an attempt to implement this at one time.  Look through
	 * git history to find it. */
	fprintf(fp, "Sorry, not implemented\n");
}

void display_initial_sids(policydb_t * p, FILE * fp)
{
	ocontext_t *cur;
	char *user, *role, *type;

	fprintf(fp, "Initial SIDs:\n");
	for (cur = p->ocontexts[OCON_ISID]; cur != NULL; cur = cur->next) {
		user = p->p_user_val_to_name[cur->context[0].user - 1];
		role = p->p_role_val_to_name[cur->context[0].role - 1];
		type = p->p_type_val_to_name[cur->context[0].type - 1];
		fprintf(fp, "\t%s: sid %d, context %s:%s:%s\n",
			cur->u.name, cur->sid[0], user, role, type);
	}
#if 0
	fprintf(fp, "Policy Initial SIDs:\n");
	for (cur = p->ocontexts[OCON_POLICYISID]; cur != NULL; cur = cur->next) {
		user = p->p_user_val_to_name[cur->context[0].user - 1];
		role = p->p_role_val_to_name[cur->context[0].role - 1];
		type = p->p_type_val_to_name[cur->context[0].type - 1];
		fprintf(fp, "\t%s: sid %d, context %s:%s:%s\n",
			cur->u.name, cur->sid[0], user, role, type);
	}
#endif
}

void display_class_set(ebitmap_t *classes, policydb_t *p, FILE *fp)
{
	unsigned int i, num = 0;

	for (i = ebitmap_startbit(classes); i < ebitmap_length(classes); i++) {
		if (!ebitmap_get_bit(classes, i))
			continue;
		num++;
		if (num > 1) {
			fprintf(fp, "{");
			break;
		}
	}

	for (i = ebitmap_startbit(classes); i < ebitmap_length(classes); i++) {
		if (ebitmap_get_bit(classes, i))
			display_id(p, fp, SYM_CLASSES, i, "");
	}

	if (num > 1)
		fprintf(fp, " }");
}

void display_role_trans(role_trans_rule_t * tr, policydb_t * p, FILE * fp)
{
	for (; tr; tr = tr->next) {
		fprintf(fp, "role transition ");
		display_mod_role_set(&tr->roles, p, fp);
		display_type_set(&tr->types, 0, p, fp);
		fprintf(fp, " :");
		display_class_set(&tr->classes, p, fp);
		display_id(p, fp, SYM_ROLES, tr->new_role - 1, "");
		fprintf(fp, "\n");
	}
}

void display_role_allow(role_allow_rule_t * ra, policydb_t * p, FILE * fp)
{
	for (; ra; ra = ra->next) {
		fprintf(fp, "role allow ");
		display_mod_role_set(&ra->roles, p, fp);
		display_mod_role_set(&ra->new_roles, p, fp);
		fprintf(fp, "\n");
	}
}

static void display_filename_trans(filename_trans_rule_t * tr, policydb_t * p, FILE * fp)
{
	fprintf(fp, "filename transition");
	for (; tr; tr = tr->next) {
		display_type_set(&tr->stypes, 0, p, fp);
		display_type_set(&tr->ttypes, 0, p, fp);
		display_id(p, fp, SYM_CLASSES, tr->tclass - 1, ":");
		display_id(p, fp, SYM_TYPES, tr->otype - 1, "");
		fprintf(fp, " %s\n", tr->name);
	}
}

int role_display_callback(hashtab_key_t key __attribute__((unused)),
			  hashtab_datum_t datum, void *data)
{
	role_datum_t *role;
	FILE *fp;

	role = (role_datum_t *) datum;
	fp = (FILE *) data;

	fprintf(fp, "role:");
	display_id(&policydb, fp, SYM_ROLES, role->s.value - 1, "");
	fprintf(fp, " types: ");
	display_type_set(&role->types, 0, &policydb, fp);
	fprintf(fp, "\n");

	return 0;
}

static int display_scope_index(scope_index_t * indices, policydb_t * p,
			       FILE * out_fp)
{
	unsigned int i;
	for (i = 0; i < SYM_NUM; i++) {
		unsigned int any_found = 0, j;
		fprintf(out_fp, "%s:", symbol_labels[i]);
		for (j = ebitmap_startbit(&indices->scope[i]);
		     j < ebitmap_length(&indices->scope[i]); j++) {
			if (ebitmap_get_bit(&indices->scope[i], j)) {
				any_found = 1;
				fprintf(out_fp, " %s",
					p->sym_val_to_name[i][j]);
				if (i == SYM_CLASSES) {
					if (j < indices->class_perms_len) {
						render_access_bitmap(indices->
								     class_perms_map
								     + j, j + 1,
								     p, out_fp);
					} else {
						fprintf(out_fp,
							"<no perms known>");
					}
				}
			}
		}
		if (!any_found) {
			fprintf(out_fp, " <empty>");
		}
		fprintf(out_fp, "\n");
	}
	return 0;
}

#if 0
int display_cond_expressions(policydb_t * p, FILE * fp)
{
	cond_node_t *cur;
	cond_av_list_t *av_cur;
	for (cur = p->cond_list; cur != NULL; cur = cur->next) {
		fprintf(fp, "expression: ");
		display_expr(p, cur->expr, fp);
		fprintf(fp, "current state: %d\n", cur->cur_state);
		fprintf(fp, "True list:\n");
		for (av_cur = cur->true_list; av_cur != NULL;
		     av_cur = av_cur->next) {
			fprintf(fp, "\t");
			render_av_rule(&av_cur->node->key, &av_cur->node->datum,
				       RENDER_CONDITIONAL, p, fp);
		}
		fprintf(fp, "False list:\n");
		for (av_cur = cur->false_list; av_cur != NULL;
		     av_cur = av_cur->next) {
			fprintf(fp, "\t");
			render_av_rule(&av_cur->node->key, &av_cur->node->datum,
				       RENDER_CONDITIONAL, p, fp);
		}
	}
	return 0;
}

int change_bool(char *name, int state, policydb_t * p, FILE * fp)
{
	cond_bool_datum_t *bool;

	bool = hashtab_search(p->p_bools.table, name);
	if (bool == NULL) {
		fprintf(fp, "Could not find bool %s\n", name);
		return -1;
	}
	bool->state = state;
	evaluate_conds(p);
	return 0;
}
#endif

int display_avdecl(avrule_decl_t * decl, int field,
		   policydb_t * policy, FILE * out_fp)
{
	fprintf(out_fp, "decl %u:%s\n", decl->decl_id,
		(decl->enabled ? " [enabled]" : ""));
	switch (field) {
	case DISPLAY_AVBLOCK_COND_AVTAB:{
			cond_list_t *cond = decl->cond_list;
			avrule_t *avrule;
			while (cond) {
				fprintf(out_fp, "expression: ");
				display_expr(&policydb, cond->expr, out_fp);
				fprintf(out_fp, "current state: %d\n",
					cond->cur_state);
				fprintf(out_fp, "True list:\n");
				avrule = cond->avtrue_list;
				while (avrule) {
					display_avrule(avrule,
						       &policydb, out_fp);
					avrule = avrule->next;
				}
				fprintf(out_fp, "False list:\n");
				avrule = cond->avfalse_list;
				while (avrule) {
					display_avrule(avrule,
						       &policydb, out_fp);
					avrule = avrule->next;
				}
				cond = cond->next;
			}
			break;
		}
	case DISPLAY_AVBLOCK_UNCOND_AVTAB:{
			avrule_t *avrule = decl->avrules;
			if (avrule == NULL) {
				fprintf(out_fp, "  <empty>\n");
			}
			while (avrule != NULL) {
				if (display_avrule(avrule, policy, out_fp))
					return -1;
				avrule = avrule->next;
			}
			break;
		}
	case DISPLAY_AVBLOCK_ROLE_TYPE_NODE:{	/* role_type_node */
			break;
		}
	case DISPLAY_AVBLOCK_ROLE_TRANS:{
			display_role_trans(decl->role_tr_rules, policy, out_fp);
			break;
		}
	case DISPLAY_AVBLOCK_ROLE_ALLOW:{
			display_role_allow(decl->role_allow_rules, policy,
					   out_fp);
			break;
		}
	case DISPLAY_AVBLOCK_REQUIRES:{
			if (display_scope_index
			    (&decl->required, policy, out_fp)) {
				return -1;
			}
			break;
		}
	case DISPLAY_AVBLOCK_DECLARES:{
			if (display_scope_index
			    (&decl->declared, policy, out_fp)) {
				return -1;
			}
			break;
		}
	case DISPLAY_AVBLOCK_FILENAME_TRANS:
		display_filename_trans(decl->filename_trans_rules, policy,
				       out_fp);
		break;
	default:{
			assert(0);
		}
	}
	return 0;		/* should never get here */
}

int display_avblock(int field, policydb_t * policy,
		    FILE * out_fp)
{
	avrule_block_t *block = policydb.global;
	while (block != NULL) {
		fprintf(out_fp, "--- begin avrule block ---\n");
		avrule_decl_t *decl = block->branch_list;
		while (decl != NULL) {
			if (display_avdecl(decl, field, policy, out_fp)) {
				return -1;
			}
			decl = decl->next;
		}
		block = block->next;
	}
	return 0;
}

int display_handle_unknown(policydb_t * p, FILE * out_fp)
{
	if (p->handle_unknown == ALLOW_UNKNOWN)
		fprintf(out_fp, "Allow unknown classes and perms\n");
	else if (p->handle_unknown == DENY_UNKNOWN)
		fprintf(out_fp, "Deny unknown classes and perms\n");
	else if (p->handle_unknown == REJECT_UNKNOWN)
		fprintf(out_fp, "Reject unknown classes and perms\n");
	return 0;
}

static int read_policy(char *filename, policydb_t * policy)
{
	FILE *in_fp;
	struct policy_file f;
	int retval;
	uint32_t buf[1];

	if ((in_fp = fopen(filename, "rb")) == NULL) {
		fprintf(stderr, "Can't open '%s':  %s\n",
			filename, strerror(errno));
		exit(1);
	}
	policy_file_init(&f);
	f.type = PF_USE_STDIO;
	f.fp = in_fp;

	/* peek at the first byte.  if they are indicative of a
	   package use the package reader, otherwise use the normal
	   policy reader */
	if (fread(buf, sizeof(uint32_t), 1, in_fp) != 1) {
		fprintf(stderr, "Could not read from policy.\n");
		exit(1);
	}
	rewind(in_fp);
	if (le32_to_cpu(buf[0]) == SEPOL_MODULE_PACKAGE_MAGIC) {
		sepol_module_package_t *package;
		if (sepol_module_package_create(&package)) {
			fprintf(stderr, "%s:  Out of memory!\n", __FUNCTION__);
			exit(1);
		}
		package->policy = (sepol_policydb_t *) policy;
		package->file_contexts = NULL;
		retval =
		    sepol_module_package_read(package,
					      (sepol_policy_file_t *) & f, 1);
		free(package->file_contexts);
	} else {
		if (policydb_init(policy)) {
			fprintf(stderr, "%s:  Out of memory!\n", __FUNCTION__);
			exit(1);
		}
		retval = policydb_read(policy, &f, 1);
	}
	fclose(in_fp);
	return retval;
}

static void link_module(policydb_t * base, FILE * out_fp)
{
	char module_name[80] = { 0 };
	int ret;
	policydb_t module, *mods = &module;

	if (base->policy_type != POLICY_BASE) {
		printf("Can only link if initial file was a base policy.\n");
		return;
	}
	printf("\nModule filename: ");
	if (fgets(module_name, sizeof(module_name), stdin) == NULL) {
		fprintf(stderr, "fgets failed at line %d: %s\n", __LINE__,
				strerror(errno));
		exit(1);
	}

	module_name[strlen(module_name) - 1] = '\0';	/* remove LF */
	if (module_name[0] == '\0') {
		return;
	}

	/* read the binary policy */
	fprintf(out_fp, "Reading module...\n");
	if (read_policy(module_name, mods)) {
		fprintf(stderr,
			"%s:  error(s) encountered while loading policy\n",
			module_name);
		exit(1);
	}
	if (module.policy_type != POLICY_MOD) {
		fprintf(stderr, "This file is not a loadable policy module.\n");
		exit(1);
	}
	if (policydb_index_classes(&module) ||
	    policydb_index_others(NULL, &module, 0)) {
		fprintf(stderr, "Could not index module.\n");
		exit(1);
	}
	ret = link_modules(NULL, base, &mods, 1, 0);
	if (ret != 0) {
		printf("Link failed (error %d)\n", ret);
		printf("(You will probably need to restart dismod.)\n");
	}
	policydb_destroy(&module);
	return;
}

static void display_policycaps(policydb_t * p, FILE * fp)
{
	ebitmap_node_t *node;
	const char *capname;
	char buf[64];
	unsigned int i;

	fprintf(fp, "policy capabilities:\n");
	ebitmap_for_each_bit(&p->policycaps, node, i) {
		if (ebitmap_node_get_bit(node, i)) {
			capname = sepol_polcap_getname(i);
			if (capname == NULL) {
				snprintf(buf, sizeof(buf), "unknown (%d)", i);
				capname = buf;
			}
			fprintf(fp, "\t%s\n", capname);
		}
	}
}

int menu(void)
{
	printf("\nSelect a command:\n");
	printf("1)  display unconditional AVTAB\n");
	printf("2)  display conditional AVTAB\n");
	printf("3)  display users\n");
	printf("4)  display bools\n");
	printf("5)  display roles\n");
	printf("6)  display types, attributes, and aliases\n");
	printf("7)  display role transitions\n");
	printf("8)  display role allows\n");
	printf("9)  Display policycon\n");
	printf("0)  Display initial SIDs\n");
	printf("\n");
	printf("a)  Display avrule requirements\n");
	printf("b)  Display avrule declarations\n");
	printf("c)  Display policy capabilities\n");
	printf("l)  Link in a module\n");
	printf("u)  Display the unknown handling setting\n");
	printf("F)  Display filename_trans rules\n");
	printf("\n");
	printf("f)  set output file\n");
	printf("m)  display menu\n");
	printf("q)  quit\n");
	return 0;
}

int main(int argc, char **argv)
{
	FILE *out_fp = stdout;
	char ans[81], OutfileName[121];

	if (argc != 2)
		usage(argv[0]);

	/* read the binary policy */
	fprintf(out_fp, "Reading policy...\n");
	if (policydb_init(&policydb)) {
		fprintf(stderr, "%s:  Out of memory!\n", __FUNCTION__);
		exit(1);
	}
	if (read_policy(argv[1], &policydb)) {
		fprintf(stderr,
			"%s:  error(s) encountered while loading policy\n",
			argv[0]);
		exit(1);
	}

	if (policydb.policy_type != POLICY_BASE &&
	    policydb.policy_type != POLICY_MOD) {
		fprintf(stderr,
			"This file is neither a base nor loadable policy module.\n");
		exit(1);
	}

	if (policydb_index_classes(&policydb)) {
		fprintf(stderr, "Error indexing classes\n");
		exit(1);
	}

	if (policydb_index_others(NULL, &policydb, 1)) {
		fprintf(stderr, "Error indexing others\n");
		exit(1);
	}

	if (policydb.policy_type == POLICY_BASE) {
		printf("Binary base policy file loaded.\n\n");
	} else {
		printf("Binary policy module file loaded.\n");
		printf("Module name: %s\n", policydb.name);
		printf("Module version: %s\n", policydb.version);
		printf("\n");
	}

	menu();
	for (;;) {
		printf("\nCommand (\'m\' for menu):  ");
		if (fgets(ans, sizeof(ans), stdin) == NULL) {
			fprintf(stderr, "fgets failed at line %d: %s\n", __LINE__,
					strerror(errno));
			continue;
		}

		switch (ans[0]) {

		case '1':
			fprintf(out_fp, "unconditional avtab:\n");
			display_avblock(DISPLAY_AVBLOCK_UNCOND_AVTAB,
					&policydb, out_fp);
			break;
		case '2':
			fprintf(out_fp, "conditional avtab:\n");
			display_avblock(DISPLAY_AVBLOCK_COND_AVTAB,
					&policydb, out_fp);
			break;
		case '3':
			display_users(&policydb, out_fp);
			break;
		case '4':
			display_bools(&policydb, out_fp);
			break;
		case '5':
			if (hashtab_map
			    (policydb.p_roles.table, role_display_callback,
			     out_fp))
				exit(1);
			break;
		case '6':
			if (display_types(&policydb, out_fp)) {
				fprintf(stderr, "Error displaying types\n");
				exit(1);
			}
			break;
		case '7':
			fprintf(out_fp, "role transitions:\n");
			display_avblock(DISPLAY_AVBLOCK_ROLE_TRANS,
					&policydb, out_fp);
			break;
		case '8':
			fprintf(out_fp, "role allows:\n");
			display_avblock(DISPLAY_AVBLOCK_ROLE_ALLOW,
					&policydb, out_fp);
			break;
		case '9':
			display_policycon(out_fp);
			break;
		case '0':
			display_initial_sids(&policydb, out_fp);
			break;
		case 'a':
			fprintf(out_fp, "avrule block requirements:\n");
			display_avblock(DISPLAY_AVBLOCK_REQUIRES,
					&policydb, out_fp);
			break;
		case 'b':
			fprintf(out_fp, "avrule block declarations:\n");
			display_avblock(DISPLAY_AVBLOCK_DECLARES,
					&policydb, out_fp);
			break;
		case 'c':
			display_policycaps(&policydb, out_fp);
			break;
		case 'u':
		case 'U':
			display_handle_unknown(&policydb, out_fp);
			break;
		case 'f':
			printf
			    ("\nFilename for output (<CR> for screen output): ");
			if (fgets(OutfileName, sizeof(OutfileName), stdin) == NULL) {
				fprintf(stderr, "fgets failed at line %d: %s\n", __LINE__,
						strerror(errno));
				break;
			}
			OutfileName[strlen(OutfileName) - 1] = '\0';	/* fix_string (remove LF) */
			if (strlen(OutfileName) == 0)
				out_fp = stdout;
			else if ((out_fp = fopen(OutfileName, "w")) == NULL) {
				fprintf(stderr, "Cannot open output file %s\n",
					OutfileName);
				out_fp = stdout;
			}
			if (out_fp != stdout)
				printf("\nOutput to file: %s\n", OutfileName);
			break;
		case 'F':
			fprintf(out_fp, "filename_trans rules:\n");
			display_avblock(DISPLAY_AVBLOCK_FILENAME_TRANS,
					&policydb, out_fp);
			break;
		case 'l':
			link_module(&policydb, out_fp);
			break;
		case 'q':
			policydb_destroy(&policydb);
			exit(0);
			break;
		case 'm':
			menu();
			break;
		default:
			printf("\nInvalid choice\n");
			menu();
			break;

		}
	}
	exit(EXIT_SUCCESS);
}
