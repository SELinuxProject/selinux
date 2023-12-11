/* Authors: Frank Mayer <mayerf@tresys.com> and Karl MacMillan <kmacmillan@tresys.com>
 *
 * Copyright (C) 2003 Tresys Technology, LLC
 *	This program is free software; you can redistribute it and/or modify
 *  	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, version 2.
 */

/* 
 * displaypol.c
 *
 * Test program to the contents of a binary policy in text
 * form.  This program currently only displays the
 * avtab (including conditional avtab) rules.
 *
 * 	displaypol binary_pol_file
 */

#include <sepol/policydb/policydb.h>
#include <sepol/policydb/avtab.h>
#include <sepol/policydb/services.h>
#include <sepol/policydb/conditional.h>
#include <sepol/policydb/util.h>
#include <sepol/policydb/polcaps.h>
#include <getopt.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>

static const struct command {
	enum {
		EOL    = 0,
		HEADER = 1,
		CMD    = 1 << 1,
		NOOPT  = 1 << 2,
	} meta;
	char cmd;
	const char *desc;
} commands[] = {
	{HEADER, 0, "\nSelect a command:"},
	{CMD,       '1',  "display unconditional AVTAB" },
	{CMD,       '2',  "display conditional AVTAB (entirely)"},
	{CMD,       '3',  "display conditional AVTAB (only ENABLED rules)"},
	{CMD,       '4',  "display conditional AVTAB (only DISABLED rules)"},
	{CMD,       '5',  "display booleans"},
	{CMD,       '6',  "display conditional expressions"},
	{CMD|NOOPT, '7',  "change a boolean value"},
	{CMD,       '8',  "display role transitions"},
	{HEADER, 0, ""},
	{CMD,       'c',  "display policy capabilities"},
	{CMD,       'C',  "display classes"},
	{CMD,       'u',  "display users"},
	{CMD,       'r',  "display roles"},
	{CMD,       't',  "display types"},
	{CMD,       'a',  "display type attributes"},
	{CMD,       'p',  "display the list of permissive types"},
	{CMD,       'U',  "display unknown handling setting"},
	{CMD,       'F',  "display filename_trans rules"},
	{HEADER, 0, ""},
	{CMD|NOOPT, 'f',  "set output file"},
	{CMD|NOOPT, 'm',  "display menu"},
	{CMD|NOOPT, 'q',  "quit"},
	{EOL,   0, "" },
};

static __attribute__((__noreturn__)) void usage(const char *progname)
{
	puts("Usage:");
	printf(" %s [OPTIONS] binary_pol_file\n\n", progname);
	puts("Options:");
	puts(" -h, --help   print this help message");
	puts(" -a, --actions ACTIONS   run non-interactively");
	puts("");
	puts("Actions:");
	for (unsigned int i = 0; commands[i].meta != EOL; i++) {
		if (commands[i].meta == HEADER
		    || commands[i].meta & NOOPT)
			continue;
		printf("  %c    %s\n", commands[i].cmd, commands[i].desc);
	}
	puts("");
	exit(1);
}

static int render_access_mask(uint32_t mask, avtab_key_t * key, policydb_t * p,
		       FILE * fp)
{
	char *perm = sepol_av_to_string(p, key->target_class, mask);
	fprintf(fp, "{");
	fprintf(fp, "%s ", perm ?: "<format-failure>");
	fprintf(fp, "}");
	free(perm);
	return 0;
}

static int render_type(uint32_t type, policydb_t * p, FILE * fp)
{
	fprintf(fp, "%s", p->p_type_val_to_name[type - 1]);
	return 0;
}

static int render_key(avtab_key_t * key, policydb_t * p, FILE * fp)
{
	char *stype, *ttype, *tclass;
	stype = p->p_type_val_to_name[key->source_type - 1];
	ttype = p->p_type_val_to_name[key->target_type - 1];
	tclass = p->p_class_val_to_name[key->target_class - 1];
	if (stype && ttype)
		fprintf(fp, "%s %s : %s ", stype, ttype, tclass);
	else if (stype)
		fprintf(fp, "%s %u : %s ", stype, key->target_type, tclass);
	else if (ttype)
		fprintf(fp, "%u %s : %s ", key->source_type, ttype, tclass);
	else
		fprintf(fp, "%u %u : %s ", key->source_type, key->target_type,
			tclass);
	return 0;
}

/* 'what' values for this function */
#define	RENDER_UNCONDITIONAL	0x0001	/* render all regardless of enabled state */
#define RENDER_ENABLED		0x0002
#define RENDER_DISABLED		0x0004
#define RENDER_CONDITIONAL	(RENDER_ENABLED|RENDER_DISABLED)

static int render_av_rule(avtab_key_t * key, avtab_datum_t * datum, uint32_t what,
		   policydb_t * p, FILE * fp)
{
	if (!(what & RENDER_UNCONDITIONAL)) {
		if (what != RENDER_CONDITIONAL && (((what & RENDER_ENABLED)
						    && !(key->
							 specified &
							 AVTAB_ENABLED))
						   || ((what & RENDER_DISABLED)
						       && (key->
							   specified &
							   AVTAB_ENABLED)))) {
			return 0;	/* doesn't match selection criteria */
		}
	}

	if (!(what & RENDER_UNCONDITIONAL)) {
		if (key->specified & AVTAB_ENABLED)
			fprintf(fp, "[enabled] ");
		else if (!(key->specified & AVTAB_ENABLED))
			fprintf(fp, "[disabled] ");
	}

	if (key->specified & AVTAB_AV) {
		if (key->specified & AVTAB_ALLOWED) {
			fprintf(fp, "allow ");
			render_key(key, p, fp);
			render_access_mask(datum->data, key, p, fp);
			fprintf(fp, ";\n");
		}
		if (key->specified & AVTAB_AUDITALLOW) {
			fprintf(fp, "auditallow ");
			render_key(key, p, fp);
			render_access_mask(datum->data, key, p, fp);
			fprintf(fp, ";\n");
		}
		if (key->specified & AVTAB_AUDITDENY) {
			fprintf(fp, "dontaudit ");
			render_key(key, p, fp);
			/* We inverse the mask for dontaudit since the mask is internally stored
			 * as a auditdeny mask */
			render_access_mask(~datum->data, key, p, fp);
			fprintf(fp, ";\n");
		}
	} else if (key->specified & AVTAB_TYPE) {
		if (key->specified & AVTAB_TRANSITION) {
			fprintf(fp, "type_transition ");
			render_key(key, p, fp);
			render_type(datum->data, p, fp);
			fprintf(fp, ";\n");
		}
		if (key->specified & AVTAB_MEMBER) {
			fprintf(fp, "type_member ");
			render_key(key, p, fp);
			render_type(datum->data, p, fp);
			fprintf(fp, ";\n");
		}
		if (key->specified & AVTAB_CHANGE) {
			fprintf(fp, "type_change ");
			render_key(key, p, fp);
			render_type(datum->data, p, fp);
			fprintf(fp, ";\n");
		}
	} else if (key->specified & AVTAB_XPERMS) {
		char *perms;

		if (key->specified & AVTAB_XPERMS_ALLOWED)
			fprintf(fp, "allowxperm ");
		else if (key->specified & AVTAB_XPERMS_AUDITALLOW)
			fprintf(fp, "auditallowxperm ");
		else if (key->specified & AVTAB_XPERMS_DONTAUDIT)
			fprintf(fp, "dontauditxperm ");
		render_key(key, p, fp);
		perms = sepol_extended_perms_to_string(datum->xperms);
		if (!perms) {
			fprintf(fp, "     ERROR: failed to format xperms\n");
			return -1;
		}
		fprintf(fp, "%s;\n", perms);
		free(perms);
	} else {
		fprintf(fp, "     ERROR: no valid rule type specified\n");
		return -1;
	}
	return 0;
}

static int display_avtab(avtab_t * a, uint32_t what, policydb_t * p, FILE * fp)
{
	unsigned int i;
	avtab_ptr_t cur;

	/* hmm...should have used avtab_map. */
	for (i = 0; i < a->nslot; i++) {
		for (cur = a->htable[i]; cur; cur = cur->next) {
			render_av_rule(&cur->key, &cur->datum, what, p, fp);
		}
	}
	fprintf(fp, "\n");
	return 0;
}

static void display_expr(policydb_t * p, cond_expr_t * exp, FILE * fp)
{

	cond_expr_t *cur;
	for (cur = exp; cur != NULL; cur = cur->next) {
		switch (cur->expr_type) {
		case COND_BOOL:
			fprintf(fp, "%s ",
				p->p_bool_val_to_name[cur->boolean - 1]);
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

static int display_cond_expressions(policydb_t * p, FILE * fp)
{
	cond_node_t *cur;
	cond_av_list_t *av_cur;

	for (cur = p->cond_list; cur != NULL; cur = cur->next) {
		fprintf(fp, "expression: ");
		display_expr(p, cur->expr, fp);
		fprintf(fp, "current state: %d\n", cur->cur_state);
		fprintf(fp, "True list:\n");
		for (av_cur = cur->true_list; av_cur != NULL; av_cur = av_cur->next) {
			fprintf(fp, "\t");
			render_av_rule(&av_cur->node->key, &av_cur->node->datum,
				       RENDER_CONDITIONAL, p, fp);
		}
		fprintf(fp, "False list:\n");
		for (av_cur = cur->false_list; av_cur != NULL; av_cur = av_cur->next) {
			fprintf(fp, "\t");
			render_av_rule(&av_cur->node->key, &av_cur->node->datum,
				       RENDER_CONDITIONAL, p, fp);
		}
	}
	return 0;
}

static int display_handle_unknown(policydb_t * p, FILE * out_fp)
{
	if (p->handle_unknown == ALLOW_UNKNOWN)
		fprintf(out_fp, "Allow unknown classes and permissions\n");
	else if (p->handle_unknown == DENY_UNKNOWN)
		fprintf(out_fp, "Deny unknown classes and permissions\n");
	else if (p->handle_unknown == REJECT_UNKNOWN)
		fprintf(out_fp, "Reject unknown classes and permissions\n");
	else
		fprintf(out_fp, "<INVALID SETTING!>\n");
	return 0;
}

static int change_bool(char *name, int state, policydb_t * p, FILE * fp)
{
	cond_bool_datum_t *boolean;

	boolean = hashtab_search(p->p_bools.table, name);
	if (boolean == NULL) {
		fprintf(fp, "Could not find bool %s\n", name);
		return -1;
	}
	boolean->state = state;
	evaluate_conds(p);
	return 0;
}

static int display_booleans(policydb_t * p, FILE *fp)
{
	uint32_t i;

	fprintf(fp, "booleans (#%u):\n", p->p_bools.table->nel);
	for (i = 0; i < p->p_bools.nprim; i++) {
		fprintf(fp, "\t%s : %d\n", p->p_bool_val_to_name[i],
			p->bool_val_to_struct[i]->state);
	}
	return 0;
}

static void display_policycaps(policydb_t * p, FILE * fp)
{
	ebitmap_node_t *node;
	const char *capname;
	char buf[64];
	unsigned int i;

	fprintf(fp, "policy capabilities:\n");
	ebitmap_for_each_positive_bit(&p->policycaps, node, i) {
		capname = sepol_polcap_getname(i);
		if (capname == NULL) {
			snprintf(buf, sizeof(buf), "unknown (%u)", i);
			capname = buf;
		}
		fprintf(fp, "\t%s\n", capname);
	}
}

static int display_classes(policydb_t * p, FILE *fp)
{
	uint32_t i;

	fprintf(fp, "classes (#%u):\n", p->p_classes.table->nel);
	for (i = 0; i < p->p_classes.nprim; i++) {
		if (!p->p_class_val_to_name[i])
			continue;

		fprintf(fp, "\t%s\n", p->p_class_val_to_name[i]);
	}
	return 0;
}

static void display_id(policydb_t *p, FILE *fp, uint32_t symbol_type,
		       uint32_t symbol_value, const char *prefix)
{
	const char *id = p->sym_val_to_name[symbol_type][symbol_value];
	fprintf(fp, " %s%s", prefix, id);
}

static void display_permissive(policydb_t *p, FILE *fp)
{
	ebitmap_node_t *node;
	unsigned int i;

	fprintf(fp, "permissive sids (#%u):\n", ebitmap_cardinality(&p->permissive_map));
	ebitmap_for_each_positive_bit(&p->permissive_map, node, i) {
		fprintf(fp, "\t");
		display_id(p, fp, SYM_TYPES, i - 1, "");
		fprintf(fp, "\n");
	}
}

static int display_users(policydb_t * p, FILE *fp)
{
	uint32_t i;

	fprintf(fp, "users (#%u):\n", p->p_users.table->nel);
	for (i = 0; i < p->p_users.nprim; i++) {
		if (!p->p_user_val_to_name[i])
			continue;

		fprintf(fp, "\t%s\n", p->p_user_val_to_name[i]);
	}
	return 0;
}

static int display_roles(policydb_t * p, FILE *fp)
{
	uint32_t i;

	fprintf(fp, "roles (#%u):\n", p->p_roles.table->nel);
	for (i = 0; i < p->p_roles.nprim; i++) {
		if (!p->p_role_val_to_name[i])
			continue;

		fprintf(fp, "\t%s\n", p->p_role_val_to_name[i]);
	}
	return 0;
}

static int display_types(policydb_t * p, FILE *fp)
{
	uint32_t i;

	fprintf(fp, "types (out of #%u):\n", p->p_types.table->nel);
	for (i = 0; i < p->p_types.nprim; i++) {
		if (!p->p_type_val_to_name[i])
			continue;

		if (p->type_val_to_struct[i]->flavor == TYPE_ATTRIB)
			continue;

		fprintf(fp, "\t%s\n", p->p_type_val_to_name[i]);
	}
	return 0;
}

static int display_attributes(policydb_t * p, FILE *fp)
{
	uint32_t i;

	fprintf(fp, "attributes (out of #%u):\n", p->p_types.table->nel);
	for (i = 0; i < p->p_types.nprim; i++) {
		if (!p->p_type_val_to_name[i])
			continue;

		if (p->type_val_to_struct[i]->flavor != TYPE_ATTRIB)
			continue;

		fprintf(fp, "\t%s\n", p->p_type_val_to_name[i]);
	}
	return 0;
}

static void display_role_trans(policydb_t *p, FILE *fp)
{
	role_trans_t *rt;

	fprintf(fp, "role_trans rules:\n");
	for (rt = p->role_tr; rt; rt = rt->next) {
		display_id(p, fp, SYM_ROLES, rt->role - 1, "");
		display_id(p, fp, SYM_TYPES, rt->type - 1, "");
		display_id(p, fp, SYM_CLASSES, rt->tclass - 1, ":");
		display_id(p, fp, SYM_ROLES, rt->new_role - 1, "");
		fprintf(fp, "\n");
	}
}

struct filenametr_display_args {
	policydb_t *p;
	FILE *fp;
};

static int filenametr_display(hashtab_key_t key,
			      hashtab_datum_t datum,
			      void *ptr)
{
	struct filename_trans_key *ft = (struct filename_trans_key *)key;
	struct filename_trans_datum *ftdatum = datum;
	struct filenametr_display_args *args = ptr;
	policydb_t *p = args->p;
	FILE *fp = args->fp;
	ebitmap_node_t *node;
	uint32_t bit;

	do {
		ebitmap_for_each_positive_bit(&ftdatum->stypes, node, bit) {
			display_id(p, fp, SYM_TYPES, bit, "");
			display_id(p, fp, SYM_TYPES, ft->ttype - 1, "");
			display_id(p, fp, SYM_CLASSES, ft->tclass - 1, ":");
			display_id(p, fp, SYM_TYPES, ftdatum->otype - 1, "");
			fprintf(fp, " %s\n", ft->name);
		}
		ftdatum = ftdatum->next;
	} while (ftdatum);

	return 0;
}


static void display_filename_trans(policydb_t *p, FILE *fp)
{
	struct filenametr_display_args args;

	fprintf(fp, "filename_trans rules:\n");
	args.p = p;
	args.fp = fp;
	hashtab_map(p->filename_trans, filenametr_display, &args);
}

static int menu(void)
{
	unsigned int i;
	for (i = 0; commands[i].meta != EOL; i++) {
		if (commands[i].meta == HEADER)
			printf("%s\n", commands[i].desc);
		else if (commands[i].meta & CMD)
			printf("%c) %s\n", commands[i].cmd, commands[i].desc);
	}
	return 0;
}

int main(int argc, char **argv)
{
	char *ops = NULL;
	char *bpol;
	FILE *out_fp = stdout;
	char ans[81], OutfileName[121];
	int fd, ret;
	struct stat sb;
	void *map;
	char *name;
	int state;
	struct policy_file pf;
	policydb_t policydb;

	if (argc < 2 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)
		usage(argv[0]);

	bpol = argv[1];
	if (strcmp (bpol, "--actions") == 0 || strcmp (bpol, "-a") == 0) {
		if (argc != 4) {
			fprintf(stderr, "%s: unexpected number of arguments\n", argv[0]);
			usage(argv[0]);
		}
		ops = argv[2];
		bpol = argv[3];
	} else if (bpol[0] == '-') {
		fprintf(stderr, "%s: unknown option: %s\n", argv[0], bpol);
		usage(argv[0]);
	}

	fd = open(bpol, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Can't open '%s':  %s\n",
			bpol, strerror(errno));
		exit(1);
	}
	if (fstat(fd, &sb) < 0) {
		fprintf(stderr, "Can't stat '%s':  %s\n",
			bpol, strerror(errno));
		exit(1);
	}
	map =
	    mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED) {
		fprintf(stderr, "Can't map '%s':  %s\n",
			bpol, strerror(errno));
		exit(1);
	}

	/* read the binary policy */
	if (!ops)
		fprintf(out_fp, "Reading policy...\n");
	policy_file_init(&pf);
	pf.type = PF_USE_MEMORY;
	pf.data = map;
	pf.len = sb.st_size;
	if (policydb_init(&policydb)) {
		fprintf(stderr, "%s:  Out of memory!\n", argv[0]);
		exit(1);
	}
	ret = policydb_read(&policydb, &pf, ops? 0: 1);
	if (ret) {
		fprintf(stderr,
			"%s:  error(s) encountered while parsing configuration\n",
			argv[0]);
		exit(1);
	}

	if (!ops)
		fprintf(stdout, "binary policy file loaded\n\n");
	close(fd);

	if (!ops)
		menu();
	for (;;) {
		if (ops) {
			puts("");
			ans[0] = *ops? *ops++: 'q';
			ans[1] = '\0';
		} else {
			printf("\nCommand (\'m\' for menu):  ");
			if (fgets(ans, sizeof(ans), stdin) == NULL) {
				if (feof(stdin))
					break;
				fprintf(stderr, "fgets failed at line %d: %s\n", __LINE__,
					strerror(errno));
				continue;
			}
		}
		switch (ans[0]) {

		case '1':
			display_avtab(&policydb.te_avtab, RENDER_UNCONDITIONAL,
				      &policydb, out_fp);
			break;
		case '2':
			display_avtab(&policydb.te_cond_avtab,
				      RENDER_CONDITIONAL, &policydb, out_fp);
			break;
		case '3':
			display_avtab(&policydb.te_cond_avtab, RENDER_ENABLED,
				      &policydb, out_fp);
			break;
		case '4':
			display_avtab(&policydb.te_cond_avtab, RENDER_DISABLED,
				      &policydb, out_fp);
			break;
		case '5':
			display_booleans(&policydb, out_fp);
			break;
		case '6':
			display_cond_expressions(&policydb, out_fp);
			break;
		case '7':
			printf("name? ");
			if (fgets(ans, sizeof(ans), stdin) == NULL) {
				fprintf(stderr, "fgets failed at line %d: %s\n", __LINE__,
						strerror(errno));
				break;
			}
			ans[strlen(ans) - 1] = 0;

			name = strdup(ans);
			if (name == NULL) {
				fprintf(stderr, "couldn't strdup string.\n");
				break;
			}

			printf("state? ");
			if (fgets(ans, sizeof(ans), stdin) == NULL) {
				fprintf(stderr, "fgets failed at line %d: %s\n", __LINE__,
						strerror(errno));
				break;
			}
			ans[strlen(ans) - 1] = 0;

			if (atoi(ans))
				state = 1;
			else
				state = 0;

			change_bool(name, state, &policydb, out_fp);
			free(name);
			break;
		case '8':
			display_role_trans(&policydb, out_fp);
			break;
		case 'a':
			display_attributes(&policydb, out_fp);
			break;
		case 'c':
			display_policycaps(&policydb, out_fp);
			break;
		case 'C':
			display_classes(&policydb, out_fp);
			break;
		case 'p':
			display_permissive(&policydb, out_fp);
			break;
		case 'r':
			display_roles(&policydb, out_fp);
			break;
		case 't':
			display_types(&policydb, out_fp);
			break;
		case 'u':
			display_users(&policydb, out_fp);
			break;
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
			display_filename_trans(&policydb, out_fp);
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
}

/* FLASK */
