/*
 * Author : Stephen Smalley, <sds@epoch.ncsc.mil> 
 */

/*
 * Updated: Trusted Computer Solutions, Inc. <dgoeddel@trustedcs.com>
 *
 *	Support for enhanced MLS infrastructure.
 *
 * Updated: David Caplan, <dac@tresys.com>
 *
 * 	Added conditional policy language extensions
 *
 * Updated: Joshua Brindle <jbrindle@tresys.com>
 *	    Karl MacMillan <kmacmillan@mentalrootkit.com>
 *          Jason Tang     <jtang@tresys.com>
 *
 *	Added support for binary policy modules
 *
 * Copyright (C) 2004-2005 Trusted Computer Solutions, Inc.
 * Copyright (C) 2003 - 2008 Tresys Technology, LLC
 * Copyright (C) 2007 Red Hat Inc.
 *	This program is free software; you can redistribute it and/or modify
 *  	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, version 2.
 */

/* FLASK */

#include <sys/types.h>
#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#ifndef IPPROTO_DCCP
#define IPPROTO_DCCP 33
#endif
#include <arpa/inet.h>
#include <stdlib.h>
#include <limits.h>
#include <inttypes.h>
#include <ctype.h>

#include <sepol/policydb/expand.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/services.h>
#include <sepol/policydb/conditional.h>
#include <sepol/policydb/flask.h>
#include <sepol/policydb/hierarchy.h>
#include <sepol/policydb/polcaps.h>
#include "queue.h"
#include "checkpolicy.h"
#include "module_compiler.h"
#include "policy_define.h"

policydb_t *policydbp;
queue_t id_queue = 0;
unsigned int pass;
char *curfile = 0;
int mlspol = 0;

extern unsigned long policydb_lineno;
extern unsigned long source_lineno;
extern unsigned int policydb_errors;
extern char source_file[PATH_MAX];

extern int yywarn(const char *msg);
extern int yyerror(const char *msg);

#define ERRORMSG_LEN 255
static char errormsg[ERRORMSG_LEN + 1] = {0};

static int id_has_dot(char *id);
static int parse_security_context(context_struct_t *c);

/* initialize all of the state variables for the scanner/parser */
void init_parser(int pass_number)
{
	policydb_lineno = 1;
	source_lineno = 1;
	policydb_errors = 0;
	pass = pass_number;
}

__attribute__ ((format(printf, 1, 2)))
void yyerror2(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(errormsg, ERRORMSG_LEN, fmt, ap);
	yyerror(errormsg);
	va_end(ap);
}

int insert_separator(int push)
{
	int error;

	if (push)
		error = queue_push(id_queue, 0);
	else
		error = queue_insert(id_queue, 0);

	if (error) {
		yyerror("queue overflow");
		return -1;
	}
	return 0;
}

int insert_id(const char *id, int push)
{
	char *newid = 0;
	int error;

	newid = (char *)malloc(strlen(id) + 1);
	if (!newid) {
		yyerror("out of memory");
		return -1;
	}
	strcpy(newid, id);
	if (push)
		error = queue_push(id_queue, (queue_element_t) newid);
	else
		error = queue_insert(id_queue, (queue_element_t) newid);

	if (error) {
		yyerror("queue overflow");
		free(newid);
		return -1;
	}
	return 0;
}

/* If the identifier has a dot within it and that its first character
   is not a dot then return 1, else return 0. */
static int id_has_dot(char *id)
{
	if (strchr(id, '.') >= id + 1) {
		return 1;
	}
	return 0;
}

int define_class(void)
{
	char *id = 0;
	class_datum_t *datum = 0;
	int ret;
	uint32_t value;

	if (pass == 2) {
		id = queue_remove(id_queue);
		free(id);
		return 0;
	}

	id = (char *)queue_remove(id_queue);
	if (!id) {
		yyerror("no class name for class definition?");
		return -1;
	}
	datum = (class_datum_t *) malloc(sizeof(class_datum_t));
	if (!datum) {
		yyerror("out of memory");
		goto bad;
	}
	memset(datum, 0, sizeof(class_datum_t));
	ret = declare_symbol(SYM_CLASSES, id, datum, &value, &value);
	switch (ret) {
	case -3:{
			yyerror("Out of memory!");
			goto bad;
		}
	case -2:{
			yyerror2("duplicate declaration of class %s", id);
			goto bad;
		}
	case -1:{
			yyerror("could not declare class here");
			goto bad;
		}
	case 0:
	case 1:{
			break;
		}
	default:{
			assert(0);	/* should never get here */
		}
	}
	datum->s.value = value;
	return 0;

      bad:
	if (id)
		free(id);
	if (datum)
		free(datum);
	return -1;
}

int define_permissive(void)
{
	char *type = NULL;
	struct type_datum *t;
	int rc = 0;

	type = queue_remove(id_queue);

	if (!type) {
		yyerror2("forgot to include type in permissive definition?");
		rc = -1;
		goto out;
	}

	if (pass == 1)
		goto out;

	if (!is_id_in_scope(SYM_TYPES, type)) {
		yyerror2("type %s is not within scope", type);
		rc = -1;
		goto out;
	}

	t = hashtab_search(policydbp->p_types.table, type);
	if (!t) {
		yyerror2("type is not defined: %s", type);
		rc = -1;
		goto out;
	}

	if (t->flavor == TYPE_ATTRIB) {
		yyerror2("attributes may not be permissive: %s\n", type);
		rc = -1;
		goto out;
	}

	t->flags |= TYPE_FLAGS_PERMISSIVE;

out:
	free(type);
	return rc;
}

int define_polcap(void)
{
	char *id = 0;
	int capnum;

	if (pass == 2) {
		id = queue_remove(id_queue);
		free(id);
		return 0;
	}

	id = (char *)queue_remove(id_queue);
	if (!id) {
		yyerror("no capability name for policycap definition?");
		goto bad;
	}

	/* Check for valid cap name -> number mapping */
	capnum = sepol_polcap_getnum(id);
	if (capnum < 0) {
		yyerror2("invalid policy capability name %s", id);
		goto bad;
	}

	/* Store it */
	if (ebitmap_set_bit(&policydbp->policycaps, capnum, TRUE)) {
		yyerror("out of memory");
		goto bad;
	}

	free(id);
	return 0;

      bad:
	free(id);
	return -1;
}

int define_initial_sid(void)
{
	char *id = 0;
	ocontext_t *newc = 0, *c, *head;

	if (pass == 2) {
		id = queue_remove(id_queue);
		free(id);
		return 0;
	}

	id = (char *)queue_remove(id_queue);
	if (!id) {
		yyerror("no sid name for SID definition?");
		return -1;
	}
	newc = (ocontext_t *) malloc(sizeof(ocontext_t));
	if (!newc) {
		yyerror("out of memory");
		goto bad;
	}
	memset(newc, 0, sizeof(ocontext_t));
	newc->u.name = id;
	context_init(&newc->context[0]);
	head = policydbp->ocontexts[OCON_ISID];

	for (c = head; c; c = c->next) {
		if (!strcmp(newc->u.name, c->u.name)) {
			yyerror2("duplicate initial SID %s", id);
			goto bad;
		}
	}

	if (head) {
		newc->sid[0] = head->sid[0] + 1;
	} else {
		newc->sid[0] = 1;
	}
	newc->next = head;
	policydbp->ocontexts[OCON_ISID] = newc;

	return 0;

      bad:
	if (id)
		free(id);
	if (newc)
		free(newc);
	return -1;
}

static int read_classes(ebitmap_t *e_classes)
{
	char *id;
	class_datum_t *cladatum;

	while ((id = queue_remove(id_queue))) {
		if (!is_id_in_scope(SYM_CLASSES, id)) {
			yyerror2("class %s is not within scope", id);
			return -1;
		}
		cladatum = hashtab_search(policydbp->p_classes.table, id);
		if (!cladatum) {
			yyerror2("unknown class %s", id);
			free(id);
			return -1;
		}
		free(id);
		if (ebitmap_set_bit(e_classes, cladatum->s.value - 1, TRUE)) {
			yyerror("Out of memory");
			return -1;
		}
	}
	return 0;
}

int define_default_user(int which)
{
	char *id;
	class_datum_t *cladatum;

	if (pass == 1) {
		while ((id = queue_remove(id_queue)))
			free(id);
		return 0;
	}

	while ((id = queue_remove(id_queue))) {
		if (!is_id_in_scope(SYM_CLASSES, id)) {
			yyerror2("class %s is not within scope", id);
			return -1;
		}
		cladatum = hashtab_search(policydbp->p_classes.table, id);
		if (!cladatum) {
			yyerror2("unknown class %s", id);
			return -1;
		}
		if (cladatum->default_user && cladatum->default_user != which) {
			yyerror2("conflicting default user information for class %s", id);
			return -1;
		}
		cladatum->default_user = which;
		free(id);
	}

	return 0;
}

int define_default_role(int which)
{
	char *id;
	class_datum_t *cladatum;

	if (pass == 1) {
		while ((id = queue_remove(id_queue)))
			free(id);
		return 0;
	}

	while ((id = queue_remove(id_queue))) {
		if (!is_id_in_scope(SYM_CLASSES, id)) {
			yyerror2("class %s is not within scope", id);
			return -1;
		}
		cladatum = hashtab_search(policydbp->p_classes.table, id);
		if (!cladatum) {
			yyerror2("unknown class %s", id);
			return -1;
		}
		if (cladatum->default_role && cladatum->default_role != which) {
			yyerror2("conflicting default role information for class %s", id);
			return -1;
		}
		cladatum->default_role = which;
		free(id);
	}

	return 0;
}

int define_default_type(int which)
{
	char *id;
	class_datum_t *cladatum;

	if (pass == 1) {
		while ((id = queue_remove(id_queue)))
			free(id);
		return 0;
	}

	while ((id = queue_remove(id_queue))) {
		if (!is_id_in_scope(SYM_CLASSES, id)) {
			yyerror2("class %s is not within scope", id);
			return -1;
		}
		cladatum = hashtab_search(policydbp->p_classes.table, id);
		if (!cladatum) {
			yyerror2("unknown class %s", id);
			return -1;
		}
		if (cladatum->default_type && cladatum->default_type != which) {
			yyerror2("conflicting default type information for class %s", id);
			return -1;
		}
		cladatum->default_type = which;
		free(id);
	}

	return 0;
}

int define_default_range(int which)
{
	char *id;
	class_datum_t *cladatum;

	if (pass == 1) {
		while ((id = queue_remove(id_queue)))
			free(id);
		return 0;
	}

	while ((id = queue_remove(id_queue))) {
		if (!is_id_in_scope(SYM_CLASSES, id)) {
			yyerror2("class %s is not within scope", id);
			return -1;
		}
		cladatum = hashtab_search(policydbp->p_classes.table, id);
		if (!cladatum) {
			yyerror2("unknown class %s", id);
			return -1;
		}
		if (cladatum->default_range && cladatum->default_range != which) {
			yyerror2("conflicting default range information for class %s", id);
			return -1;
		}
		cladatum->default_range = which;
		free(id);
	}

	return 0;
}

int define_common_perms(void)
{
	char *id = 0, *perm = 0;
	common_datum_t *comdatum = 0;
	perm_datum_t *perdatum = 0;
	int ret;

	if (pass == 2) {
		while ((id = queue_remove(id_queue)))
			free(id);
		return 0;
	}

	id = (char *)queue_remove(id_queue);
	if (!id) {
		yyerror("no common name for common perm definition?");
		return -1;
	}
	comdatum = hashtab_search(policydbp->p_commons.table, id);
	if (comdatum) {
		yyerror2("duplicate declaration for common %s\n", id);
		return -1;
	}
	comdatum = (common_datum_t *) malloc(sizeof(common_datum_t));
	if (!comdatum) {
		yyerror("out of memory");
		goto bad;
	}
	memset(comdatum, 0, sizeof(common_datum_t));
	ret = hashtab_insert(policydbp->p_commons.table,
			     (hashtab_key_t) id, (hashtab_datum_t) comdatum);

	if (ret == SEPOL_EEXIST) {
		yyerror("duplicate common definition");
		goto bad;
	}
	if (ret == SEPOL_ENOMEM) {
		yyerror("hash table overflow");
		goto bad;
	}
	comdatum->s.value = policydbp->p_commons.nprim + 1;
	if (symtab_init(&comdatum->permissions, PERM_SYMTAB_SIZE)) {
		yyerror("out of memory");
		goto bad;
	}
	policydbp->p_commons.nprim++;
	while ((perm = queue_remove(id_queue))) {
		perdatum = (perm_datum_t *) malloc(sizeof(perm_datum_t));
		if (!perdatum) {
			yyerror("out of memory");
			goto bad_perm;
		}
		memset(perdatum, 0, sizeof(perm_datum_t));
		perdatum->s.value = comdatum->permissions.nprim + 1;

		if (perdatum->s.value > (sizeof(sepol_access_vector_t) * 8)) {
			yyerror
			    ("too many permissions to fit in an access vector");
			goto bad_perm;
		}
		ret = hashtab_insert(comdatum->permissions.table,
				     (hashtab_key_t) perm,
				     (hashtab_datum_t) perdatum);

		if (ret == SEPOL_EEXIST) {
			yyerror2("duplicate permission %s in common %s", perm,
				 id);
			goto bad_perm;
		}
		if (ret == SEPOL_ENOMEM) {
			yyerror("hash table overflow");
			goto bad_perm;
		}
		comdatum->permissions.nprim++;
	}

	return 0;

      bad:
	if (id)
		free(id);
	if (comdatum)
		free(comdatum);
	return -1;

      bad_perm:
	if (perm)
		free(perm);
	if (perdatum)
		free(perdatum);
	return -1;
}

int define_av_perms(int inherits)
{
	char *id;
	class_datum_t *cladatum;
	common_datum_t *comdatum;
	perm_datum_t *perdatum = 0, *perdatum2 = 0;
	int ret;

	if (pass == 2) {
		while ((id = queue_remove(id_queue)))
			free(id);
		return 0;
	}

	id = (char *)queue_remove(id_queue);
	if (!id) {
		yyerror("no tclass name for av perm definition?");
		return -1;
	}
	cladatum = (class_datum_t *) hashtab_search(policydbp->p_classes.table,
						    (hashtab_key_t) id);
	if (!cladatum) {
		yyerror2("class %s is not defined", id);
		goto bad;
	}
	free(id);

	if (cladatum->comdatum || cladatum->permissions.nprim) {
		yyerror("duplicate access vector definition");
		return -1;
	}
	if (symtab_init(&cladatum->permissions, PERM_SYMTAB_SIZE)) {
		yyerror("out of memory");
		return -1;
	}
	if (inherits) {
		id = (char *)queue_remove(id_queue);
		if (!id) {
			yyerror
			    ("no inherits name for access vector definition?");
			return -1;
		}
		comdatum =
		    (common_datum_t *) hashtab_search(policydbp->p_commons.
						      table,
						      (hashtab_key_t) id);

		if (!comdatum) {
			yyerror2("common %s is not defined", id);
			goto bad;
		}
		cladatum->comkey = id;
		cladatum->comdatum = comdatum;

		/*
		 * Class-specific permissions start with values 
		 * after the last common permission.
		 */
		cladatum->permissions.nprim += comdatum->permissions.nprim;
	}
	while ((id = queue_remove(id_queue))) {
		perdatum = (perm_datum_t *) malloc(sizeof(perm_datum_t));
		if (!perdatum) {
			yyerror("out of memory");
			goto bad;
		}
		memset(perdatum, 0, sizeof(perm_datum_t));
		perdatum->s.value = ++cladatum->permissions.nprim;

		if (perdatum->s.value > (sizeof(sepol_access_vector_t) * 8)) {
			yyerror
			    ("too many permissions to fit in an access vector");
			goto bad;
		}
		if (inherits) {
			/*
			 * Class-specific permissions and 
			 * common permissions exist in the same
			 * name space.
			 */
			perdatum2 =
			    (perm_datum_t *) hashtab_search(cladatum->comdatum->
							    permissions.table,
							    (hashtab_key_t) id);
			if (perdatum2) {
				yyerror2("permission %s conflicts with an "
					 "inherited permission", id);
				goto bad;
			}
		}
		ret = hashtab_insert(cladatum->permissions.table,
				     (hashtab_key_t) id,
				     (hashtab_datum_t) perdatum);

		if (ret == SEPOL_EEXIST) {
			yyerror2("duplicate permission %s", id);
			goto bad;
		}
		if (ret == SEPOL_ENOMEM) {
			yyerror("hash table overflow");
			goto bad;
		}
		if (add_perm_to_class(perdatum->s.value, cladatum->s.value)) {
			yyerror("out of memory");
			goto bad;
		}
	}

	return 0;

      bad:
	if (id)
		free(id);
	if (perdatum)
		free(perdatum);
	return -1;
}

int define_sens(void)
{
	char *id;
	mls_level_t *level = 0;
	level_datum_t *datum = 0, *aliasdatum = 0;
	int ret;
	uint32_t value;		/* dummy variable -- its value is never used */

	if (!mlspol) {
		yyerror("sensitivity definition in non-MLS configuration");
		return -1;
	}

	if (pass == 2) {
		while ((id = queue_remove(id_queue)))
			free(id);
		return 0;
	}

	id = (char *)queue_remove(id_queue);
	if (!id) {
		yyerror("no sensitivity name for sensitivity definition?");
		return -1;
	}
	if (id_has_dot(id)) {
		yyerror("sensitivity identifiers may not contain periods");
		goto bad;
	}
	level = (mls_level_t *) malloc(sizeof(mls_level_t));
	if (!level) {
		yyerror("out of memory");
		goto bad;
	}
	mls_level_init(level);
	level->sens = 0;	/* actual value set in define_dominance */
	ebitmap_init(&level->cat);	/* actual value set in define_level */

	datum = (level_datum_t *) malloc(sizeof(level_datum_t));
	if (!datum) {
		yyerror("out of memory");
		goto bad;
	}
	level_datum_init(datum);
	datum->isalias = FALSE;
	datum->level = level;

	ret = declare_symbol(SYM_LEVELS, id, datum, &value, &value);
	switch (ret) {
	case -3:{
			yyerror("Out of memory!");
			goto bad;
		}
	case -2:{
			yyerror("duplicate declaration of sensitivity level");
			goto bad;
		}
	case -1:{
			yyerror("could not declare sensitivity level here");
			goto bad;
		}
	case 0:
	case 1:{
			break;
		}
	default:{
			assert(0);	/* should never get here */
		}
	}

	while ((id = queue_remove(id_queue))) {
		if (id_has_dot(id)) {
			yyerror("sensitivity aliases may not contain periods");
			goto bad_alias;
		}
		aliasdatum = (level_datum_t *) malloc(sizeof(level_datum_t));
		if (!aliasdatum) {
			yyerror("out of memory");
			goto bad_alias;
		}
		level_datum_init(aliasdatum);
		aliasdatum->isalias = TRUE;
		aliasdatum->level = level;

		ret = declare_symbol(SYM_LEVELS, id, aliasdatum, NULL, &value);
		switch (ret) {
		case -3:{
				yyerror("Out of memory!");
				goto bad_alias;
			}
		case -2:{
				yyerror
				    ("duplicate declaration of sensitivity alias");
				goto bad_alias;
			}
		case -1:{
				yyerror
				    ("could not declare sensitivity alias here");
				goto bad_alias;
			}
		case 0:
		case 1:{
				break;
			}
		default:{
				assert(0);	/* should never get here */
			}
		}
	}

	return 0;

      bad:
	if (id)
		free(id);
	if (level)
		free(level);
	if (datum) {
		level_datum_destroy(datum);
		free(datum);
	}
	return -1;

      bad_alias:
	if (id)
		free(id);
	if (aliasdatum) {
		level_datum_destroy(aliasdatum);
		free(aliasdatum);
	}
	return -1;
}

int define_dominance(void)
{
	level_datum_t *datum;
	uint32_t order;
	char *id;

	if (!mlspol) {
		yyerror("dominance definition in non-MLS configuration");
		return -1;
	}

	if (pass == 2) {
		while ((id = queue_remove(id_queue)))
			free(id);
		return 0;
	}

	order = 0;
	while ((id = (char *)queue_remove(id_queue))) {
		datum =
		    (level_datum_t *) hashtab_search(policydbp->p_levels.table,
						     (hashtab_key_t) id);
		if (!datum) {
			yyerror2("unknown sensitivity %s used in dominance "
				 "definition", id);
			free(id);
			return -1;
		}
		if (datum->level->sens != 0) {
			yyerror2("sensitivity %s occurs multiply in dominance "
				 "definition", id);
			free(id);
			return -1;
		}
		datum->level->sens = ++order;

		/* no need to keep sensitivity name */
		free(id);
	}

	if (order != policydbp->p_levels.nprim) {
		yyerror
		    ("all sensitivities must be specified in dominance definition");
		return -1;
	}
	return 0;
}

int define_category(void)
{
	char *id;
	cat_datum_t *datum = 0, *aliasdatum = 0;
	int ret;
	uint32_t value;

	if (!mlspol) {
		yyerror("category definition in non-MLS configuration");
		return -1;
	}

	if (pass == 2) {
		while ((id = queue_remove(id_queue)))
			free(id);
		return 0;
	}

	id = (char *)queue_remove(id_queue);
	if (!id) {
		yyerror("no category name for category definition?");
		return -1;
	}
	if (id_has_dot(id)) {
		yyerror("category identifiers may not contain periods");
		goto bad;
	}
	datum = (cat_datum_t *) malloc(sizeof(cat_datum_t));
	if (!datum) {
		yyerror("out of memory");
		goto bad;
	}
	cat_datum_init(datum);
	datum->isalias = FALSE;

	ret = declare_symbol(SYM_CATS, id, datum, &value, &value);
	switch (ret) {
	case -3:{
			yyerror("Out of memory!");
			goto bad;
		}
	case -2:{
			yyerror("duplicate declaration of category");
			goto bad;
		}
	case -1:{
			yyerror("could not declare category here");
			goto bad;
		}
	case 0:
	case 1:{
			break;
		}
	default:{
			assert(0);	/* should never get here */
		}
	}
	datum->s.value = value;

	while ((id = queue_remove(id_queue))) {
		if (id_has_dot(id)) {
			yyerror("category aliases may not contain periods");
			goto bad_alias;
		}
		aliasdatum = (cat_datum_t *) malloc(sizeof(cat_datum_t));
		if (!aliasdatum) {
			yyerror("out of memory");
			goto bad_alias;
		}
		cat_datum_init(aliasdatum);
		aliasdatum->isalias = TRUE;
		aliasdatum->s.value = datum->s.value;

		ret =
		    declare_symbol(SYM_CATS, id, aliasdatum, NULL,
				   &datum->s.value);
		switch (ret) {
		case -3:{
				yyerror("Out of memory!");
				goto bad_alias;
			}
		case -2:{
				yyerror
				    ("duplicate declaration of category aliases");
				goto bad_alias;
			}
		case -1:{
				yyerror
				    ("could not declare category aliases here");
				goto bad_alias;
			}
		case 0:
		case 1:{
				break;
			}
		default:{
				assert(0);	/* should never get here */
			}
		}
	}

	return 0;

      bad:
	if (id)
		free(id);
	if (datum) {
		cat_datum_destroy(datum);
		free(datum);
	}
	return -1;

      bad_alias:
	if (id)
		free(id);
	if (aliasdatum) {
		cat_datum_destroy(aliasdatum);
		free(aliasdatum);
	}
	return -1;
}

static int clone_level(hashtab_key_t key __attribute__ ((unused)), hashtab_datum_t datum, void *arg)
{
	level_datum_t *levdatum = (level_datum_t *) datum;
	mls_level_t *level = (mls_level_t *) arg, *newlevel;

	if (levdatum->level == level) {
		levdatum->defined = 1;
		if (!levdatum->isalias)
			return 0;
		newlevel = (mls_level_t *) malloc(sizeof(mls_level_t));
		if (!newlevel)
			return -1;
		if (mls_level_cpy(newlevel, level)) {
			free(newlevel);
			return -1;
		}
		levdatum->level = newlevel;
	}
	return 0;
}

int define_level(void)
{
	char *id;
	level_datum_t *levdatum;

	if (!mlspol) {
		yyerror("level definition in non-MLS configuration");
		return -1;
	}

	if (pass == 2) {
		while ((id = queue_remove(id_queue)))
			free(id);
		return 0;
	}

	id = (char *)queue_remove(id_queue);
	if (!id) {
		yyerror("no level name for level definition?");
		return -1;
	}
	levdatum = (level_datum_t *) hashtab_search(policydbp->p_levels.table,
						    (hashtab_key_t) id);
	if (!levdatum) {
		yyerror2("unknown sensitivity %s used in level definition", id);
		free(id);
		return -1;
	}
	if (ebitmap_length(&levdatum->level->cat)) {
		yyerror2("sensitivity %s used in multiple level definitions",
			 id);
		free(id);
		return -1;
	}
	free(id);

	levdatum->defined = 1;

	while ((id = queue_remove(id_queue))) {
		cat_datum_t *cdatum;
		int range_start, range_end, i;

		if (id_has_dot(id)) {
			char *id_start = id;
			char *id_end = strchr(id, '.');

			*(id_end++) = '\0';

			cdatum =
			    (cat_datum_t *) hashtab_search(policydbp->p_cats.
							   table,
							   (hashtab_key_t)
							   id_start);
			if (!cdatum) {
				yyerror2("unknown category %s", id_start);
				free(id);
				return -1;
			}
			range_start = cdatum->s.value - 1;
			cdatum =
			    (cat_datum_t *) hashtab_search(policydbp->p_cats.
							   table,
							   (hashtab_key_t)
							   id_end);
			if (!cdatum) {
				yyerror2("unknown category %s", id_end);
				free(id);
				return -1;
			}
			range_end = cdatum->s.value - 1;

			if (range_end < range_start) {
				yyerror2("category range is invalid");
				free(id);
				return -1;
			}
		} else {
			cdatum =
			    (cat_datum_t *) hashtab_search(policydbp->p_cats.
							   table,
							   (hashtab_key_t) id);
			range_start = range_end = cdatum->s.value - 1;
		}

		for (i = range_start; i <= range_end; i++) {
			if (ebitmap_set_bit(&levdatum->level->cat, i, TRUE)) {
				yyerror("out of memory");
				free(id);
				return -1;
			}
		}

		free(id);
	}

	if (hashtab_map
	    (policydbp->p_levels.table, clone_level, levdatum->level)) {
		yyerror("out of memory");
		return -1;
	}

	return 0;
}

int define_attrib(void)
{
	if (pass == 2) {
		free(queue_remove(id_queue));
		return 0;
	}

	if (declare_type(TRUE, TRUE) == NULL) {
		return -1;
	}
	return 0;
}

static int add_aliases_to_type(type_datum_t * type)
{
	char *id;
	type_datum_t *aliasdatum = NULL;
	int ret;
	while ((id = queue_remove(id_queue))) {
		if (id_has_dot(id)) {
			free(id);
			yyerror
			    ("type alias identifiers may not contain periods");
			return -1;
		}
		aliasdatum = (type_datum_t *) malloc(sizeof(type_datum_t));
		if (!aliasdatum) {
			free(id);
			yyerror("Out of memory!");
			return -1;
		}
		memset(aliasdatum, 0, sizeof(type_datum_t));
		aliasdatum->s.value = type->s.value;

		ret = declare_symbol(SYM_TYPES, id, aliasdatum,
				     NULL, &aliasdatum->s.value);
		switch (ret) {
		case -3:{
				yyerror("Out of memory!");
				goto cleanup;
			}
		case -2:{
				yyerror2("duplicate declaration of alias %s",
					 id);
				goto cleanup;
			}
		case -1:{
				yyerror("could not declare alias here");
				goto cleanup;
			}
		case 0:	 	break;
		case 1:{
				/* ret == 1 means the alias was required and therefore already
				 * has a value. Set it up as an alias with a different primary. */
				type_datum_destroy(aliasdatum);
				free(aliasdatum);

				aliasdatum = hashtab_search(policydbp->symtab[SYM_TYPES].table, id);
				assert(aliasdatum);

				aliasdatum->primary = type->s.value;
				aliasdatum->flavor = TYPE_ALIAS;

				break;
			}
		default:{
				assert(0);	/* should never get here */
			}
		}
	}
	return 0;
      cleanup:
	free(id);
	type_datum_destroy(aliasdatum);
	free(aliasdatum);
	return -1;
}

int define_typealias(void)
{
	char *id;
	type_datum_t *t;

	if (pass == 2) {
		while ((id = queue_remove(id_queue)))
			free(id);
		return 0;
	}

	id = (char *)queue_remove(id_queue);
	if (!id) {
		yyerror("no type name for typealias definition?");
		return -1;
	}

	if (!is_id_in_scope(SYM_TYPES, id)) {
		yyerror2("type %s is not within scope", id);
		free(id);
		return -1;
	}
	t = hashtab_search(policydbp->p_types.table, id);
	if (!t || t->flavor == TYPE_ATTRIB) {
		yyerror2("unknown type %s, or it was already declared as an "
			 "attribute", id);
		free(id);
		return -1;
	}
	free(id);
	return add_aliases_to_type(t);
}

int define_typeattribute(void)
{
	char *id;
	type_datum_t *t, *attr;

	if (pass == 2) {
		while ((id = queue_remove(id_queue)))
			free(id);
		return 0;
	}

	id = (char *)queue_remove(id_queue);
	if (!id) {
		yyerror("no type name for typeattribute definition?");
		return -1;
	}

	if (!is_id_in_scope(SYM_TYPES, id)) {
		yyerror2("type %s is not within scope", id);
		free(id);
		return -1;
	}
	t = hashtab_search(policydbp->p_types.table, id);
	if (!t || t->flavor == TYPE_ATTRIB) {
		yyerror2("unknown type %s", id);
		free(id);
		return -1;
	}
	free(id);

	while ((id = queue_remove(id_queue))) {
		if (!is_id_in_scope(SYM_TYPES, id)) {
			yyerror2("attribute %s is not within scope", id);
			free(id);
			return -1;
		}
		attr = hashtab_search(policydbp->p_types.table, id);
		if (!attr) {
			/* treat it as a fatal error */
			yyerror2("attribute %s is not declared", id);
			free(id);
			return -1;
		}

		if (attr->flavor != TYPE_ATTRIB) {
			yyerror2("%s is a type, not an attribute", id);
			free(id);
			return -1;
		}

		if ((attr = get_local_type(id, attr->s.value, 1)) == NULL) {
			yyerror("Out of memory!");
			return -1;
		}

		if (ebitmap_set_bit(&attr->types, (t->s.value - 1), TRUE)) {
			yyerror("out of memory");
			return -1;
		}
	}

	return 0;
}

static int define_typebounds_helper(char *bounds_id, char *type_id)
{
	type_datum_t *bounds, *type;

	if (!is_id_in_scope(SYM_TYPES, bounds_id)) {
		yyerror2("type %s is not within scope", bounds_id);
		return -1;
	}

	bounds = hashtab_search(policydbp->p_types.table, bounds_id);
	if (!bounds || bounds->flavor == TYPE_ATTRIB) {
		yyerror2("hoge unknown type %s", bounds_id);
		return -1;
	}

	if (!is_id_in_scope(SYM_TYPES, type_id)) {
		yyerror2("type %s is not within scope", type_id);
		return -1;
	}

	type = hashtab_search(policydbp->p_types.table, type_id);
	if (!type || type->flavor == TYPE_ATTRIB) {
		yyerror2("type %s is not declared", type_id);
		return -1;
	}

	if (type->flavor == TYPE_TYPE && !type->primary) {
		type = policydbp->type_val_to_struct[type->s.value - 1];
	} else if (type->flavor == TYPE_ALIAS) {
		type = policydbp->type_val_to_struct[type->primary - 1];
	}

	if (!type->bounds)
		type->bounds = bounds->s.value;
	else if (type->bounds != bounds->s.value) {
		yyerror2("type %s has inconsistent master {%s,%s}",
			 type_id,
			 policydbp->p_type_val_to_name[type->bounds - 1],
			 policydbp->p_type_val_to_name[bounds->s.value - 1]);
		return -1;
	}

	return 0;
}

int define_typebounds(void)
{
	char *bounds, *id;

	if (pass == 1) {
		while ((id = queue_remove(id_queue)))
			free(id);
		return 0;
	}

	bounds = (char *) queue_remove(id_queue);
	if (!bounds) {
		yyerror("no type name for typebounds definition?");
		return -1;
	}

	while ((id = queue_remove(id_queue))) {
		if (define_typebounds_helper(bounds, id))
			return -1;
		free(id);
	}
	free(bounds);

	return 0;
}

int define_type(int alias)
{
	char *id;
	type_datum_t *datum, *attr;

	if (pass == 2) {
		/*
		 * If type name contains ".", we have to define boundary
		 * relationship implicitly to keep compatibility with
		 * old name based hierarchy.
		 */
		if ((id = queue_remove(id_queue))) {
			char *bounds, *delim;

			if ((delim = strrchr(id, '.'))
			    && (bounds = strdup(id))) {
				bounds[(size_t)(delim - id)] = '\0';

				if (define_typebounds_helper(bounds, id))
					return -1;
				free(bounds);
			}
			free(id);
		}

		if (alias) {
			while ((id = queue_remove(id_queue)))
				free(id);
		}

		while ((id = queue_remove(id_queue)))
			free(id);
		return 0;
	}

	if ((datum = declare_type(TRUE, FALSE)) == NULL) {
		return -1;
	}

	if (alias) {
		if (add_aliases_to_type(datum) == -1) {
			return -1;
		}
	}

	while ((id = queue_remove(id_queue))) {
		if (!is_id_in_scope(SYM_TYPES, id)) {
			yyerror2("attribute %s is not within scope", id);
			free(id);
			return -1;
		}
		attr = hashtab_search(policydbp->p_types.table, id);
		if (!attr) {
			/* treat it as a fatal error */
			yyerror2("attribute %s is not declared", id);
			free(id);
			return -1;
		}

		if (attr->flavor != TYPE_ATTRIB) {
			yyerror2("%s is a type, not an attribute", id);
			free(id);
			return -1;
		}

		if ((attr = get_local_type(id, attr->s.value, 1)) == NULL) {
			yyerror("Out of memory!");
			return -1;
		}

		if (ebitmap_set_bit(&attr->types, datum->s.value - 1, TRUE)) {
			yyerror("Out of memory");
			return -1;
		}
	}

	return 0;
}

struct val_to_name {
	unsigned int val;
	char *name;
};

/* Adds a type, given by its textual name, to a typeset.  If *add is
   0, then add the type to the negative set; otherwise if *add is 1
   then add it to the positive side. */
static int set_types(type_set_t * set, char *id, int *add, char starallowed)
{
	type_datum_t *t;

	if (strcmp(id, "*") == 0) {
		free(id);
		if (!starallowed) {
			yyerror("* not allowed in this type of rule");
			return -1;
		}
		/* set TYPE_STAR flag */
		set->flags = TYPE_STAR;
		*add = 1;
		return 0;
	}

	if (strcmp(id, "~") == 0) {
		free(id);
		if (!starallowed) {
			yyerror("~ not allowed in this type of rule");
			return -1;
		}
		/* complement the set */
		set->flags = TYPE_COMP;
		*add = 1;
		return 0;
	}

	if (strcmp(id, "-") == 0) {
		*add = 0;
		free(id);
		return 0;
	}

	if (!is_id_in_scope(SYM_TYPES, id)) {
		yyerror2("type %s is not within scope", id);
		free(id);
		return -1;
	}
	t = hashtab_search(policydbp->p_types.table, id);
	if (!t) {
		yyerror2("unknown type %s", id);
		free(id);
		return -1;
	}

	if (*add == 0) {
		if (ebitmap_set_bit(&set->negset, t->s.value - 1, TRUE))
			goto oom;
	} else {
		if (ebitmap_set_bit(&set->types, t->s.value - 1, TRUE))
			goto oom;
	}
	free(id);
	*add = 1;
	return 0;
      oom:
	yyerror("Out of memory");
	free(id);
	return -1;
}

int define_compute_type_helper(int which, avrule_t ** rule)
{
	char *id;
	type_datum_t *datum;
	ebitmap_t tclasses;
	ebitmap_node_t *node;
	avrule_t *avrule;
	class_perm_node_t *perm;
	uint32_t i;
	int add = 1;

	avrule = malloc(sizeof(avrule_t));
	if (!avrule) {
		yyerror("out of memory");
		return -1;
	}
	avrule_init(avrule);
	avrule->specified = which;
	avrule->line = policydb_lineno;
	avrule->source_line = source_lineno;
	avrule->source_filename = strdup(source_file);
	if (!avrule->source_filename) {
		yyerror("out of memory");
		return -1;
	}

	while ((id = queue_remove(id_queue))) {
		if (set_types(&avrule->stypes, id, &add, 0))
			goto bad;
	}
	add = 1;
	while ((id = queue_remove(id_queue))) {
		if (set_types(&avrule->ttypes, id, &add, 0))
			goto bad;
	}

	ebitmap_init(&tclasses);
	if (read_classes(&tclasses))
		goto bad;

	id = (char *)queue_remove(id_queue);
	if (!id) {
		yyerror("no newtype?");
		goto bad;
	}
	if (!is_id_in_scope(SYM_TYPES, id)) {
		yyerror2("type %s is not within scope", id);
		free(id);
		goto bad;
	}
	datum = (type_datum_t *) hashtab_search(policydbp->p_types.table,
						(hashtab_key_t) id);
	if (!datum || datum->flavor == TYPE_ATTRIB) {
		yyerror2("unknown type %s", id);
		free(id);
		goto bad;
	}
	free(id);

	ebitmap_for_each_bit(&tclasses, node, i) {
		if (ebitmap_node_get_bit(node, i)) {
			perm = malloc(sizeof(class_perm_node_t));
			if (!perm) {
				yyerror("out of memory");
				goto bad;
			}
			class_perm_node_init(perm);
			perm->tclass = i + 1;
			perm->data = datum->s.value;
			perm->next = avrule->perms;
			avrule->perms = perm;
		}
	}
	ebitmap_destroy(&tclasses);

	*rule = avrule;
	return 0;

      bad:
	avrule_destroy(avrule);
	free(avrule);
	return -1;
}

int define_compute_type(int which)
{
	char *id;
	avrule_t *avrule;

	if (pass == 1) {
		while ((id = queue_remove(id_queue)))
			free(id);
		while ((id = queue_remove(id_queue)))
			free(id);
		while ((id = queue_remove(id_queue)))
			free(id);
		id = queue_remove(id_queue);
		free(id);
		return 0;
	}

	if (define_compute_type_helper(which, &avrule))
		return -1;

	append_avrule(avrule);
	return 0;
}

avrule_t *define_cond_compute_type(int which)
{
	char *id;
	avrule_t *avrule;

	if (pass == 1) {
		while ((id = queue_remove(id_queue)))
			free(id);
		while ((id = queue_remove(id_queue)))
			free(id);
		while ((id = queue_remove(id_queue)))
			free(id);
		id = queue_remove(id_queue);
		free(id);
		return (avrule_t *) 1;
	}

	if (define_compute_type_helper(which, &avrule))
		return COND_ERR;

	return avrule;
}

int define_bool_tunable(int is_tunable)
{
	char *id, *bool_value;
	cond_bool_datum_t *datum;
	int ret;
	uint32_t value;

	if (pass == 2) {
		while ((id = queue_remove(id_queue)))
			free(id);
		return 0;
	}

	id = (char *)queue_remove(id_queue);
	if (!id) {
		yyerror("no identifier for bool definition?");
		return -1;
	}
	if (id_has_dot(id)) {
		free(id);
		yyerror("boolean identifiers may not contain periods");
		return -1;
	}
	datum = (cond_bool_datum_t *) malloc(sizeof(cond_bool_datum_t));
	if (!datum) {
		yyerror("out of memory");
		free(id);
		return -1;
	}
	memset(datum, 0, sizeof(cond_bool_datum_t));
	if (is_tunable)
		datum->flags |= COND_BOOL_FLAGS_TUNABLE;
	ret = declare_symbol(SYM_BOOLS, id, datum, &value, &value);
	switch (ret) {
	case -3:{
			yyerror("Out of memory!");
			goto cleanup;
		}
	case -2:{
			yyerror2("duplicate declaration of boolean %s", id);
			goto cleanup;
		}
	case -1:{
			yyerror("could not declare boolean here");
			goto cleanup;
		}
	case 0:
	case 1:{
			break;
		}
	default:{
			assert(0);	/* should never get here */
		}
	}
	datum->s.value = value;

	bool_value = (char *)queue_remove(id_queue);
	if (!bool_value) {
		yyerror("no default value for bool definition?");
		return -1;
	}

	datum->state = (int)(bool_value[0] == 'T') ? 1 : 0;
	free(bool_value);
	return 0;
      cleanup:
	cond_destroy_bool(id, datum, NULL);
	return -1;
}

avrule_t *define_cond_pol_list(avrule_t * avlist, avrule_t * sl)
{
	if (pass == 1) {
		/* return something so we get through pass 1 */
		return (avrule_t *) 1;
	}

	if (sl == NULL) {
		/* This is a require block, return previous list */
		return avlist;
	}

	/* prepend the new avlist to the pre-existing one */
	sl->next = avlist;
	return sl;
}

typedef struct av_ioctl_range {
	uint16_t low;
	uint16_t high;
} av_ioctl_range_t;

struct av_ioctl_range_list {
	uint8_t omit;
	av_ioctl_range_t range;
	struct av_ioctl_range_list *next;
};

int avrule_sort_ioctls(struct av_ioctl_range_list **rangehead)
{
	struct av_ioctl_range_list *r, *r2, *sorted, *sortedhead = NULL;

	/* order list by range.low */
	for (r = *rangehead; r != NULL; r = r->next) {
		sorted = malloc(sizeof(struct av_ioctl_range_list));
		if (sorted == NULL)
			goto error;
		memcpy(sorted, r, sizeof(struct av_ioctl_range_list));
		sorted->next = NULL;
		if (sortedhead == NULL) {
			sortedhead = sorted;
			continue;
		}
	        for (r2 = sortedhead; r2 != NULL; r2 = r2->next) {
			if (sorted->range.low < r2->range.low) {
				/* range is the new head */
				sorted->next = r2;
				sortedhead = sorted;
				break;
			} else if ((r2 ->next != NULL) &&
					(r->range.low < r2->next->range.low)) {
				/* insert range between elements */
				sorted->next = r2->next;
				r2->next = sorted;
				break;
			} else if (r2->next == NULL) {
				/* range is the new tail*/
				r2->next = sorted;
				break;
			}
		}
	}

	r = *rangehead;
	while (r != NULL) {
		r2 = r;
		r = r->next;
		free(r2);
	}
	*rangehead = sortedhead;
	return 0;
error:
	yyerror("out of memory");
	return -1;
}

int avrule_merge_ioctls(struct av_ioctl_range_list **rangehead)
{
	struct av_ioctl_range_list *r, *tmp;
	r = *rangehead;
	while (r != NULL && r->next != NULL) {
		/* merge */
		if ((r->range.high + 1) >= r->next->range.low) {
			/* keep the higher of the two */
			if (r->range.high < r->next->range.high)
				r->range.high = r->next->range.high;
			tmp = r->next;
			r->next = r->next->next;
			free(tmp);
			continue;
		}
		r = r->next;
	}
	return 0;
}

int avrule_read_ioctls(struct av_ioctl_range_list **rangehead)
{
	char *id;
	struct av_ioctl_range_list *rnew, *r = NULL;
	*rangehead = NULL;
	uint8_t omit = 0;

	/* read in all the ioctl commands */
	while ((id = queue_remove(id_queue))) {
		if (strcmp(id,"~") == 0) {
			/* these are values to be omitted */
			free(id);
			omit = 1;
		} else if (strcmp(id,"-") == 0) {
			/* high value of range */
			free(id);
			id = queue_remove(id_queue);
			r->range.high = (uint16_t) strtoul(id,NULL,0);
			if (r->range.high < r->range.low) {
				yyerror("Ioctl ranges must be in ascending order.");
				return -1;
			}
			free(id);
		} else {
			/* read in new low value */
			rnew = malloc(sizeof(struct av_ioctl_range_list));
			if (rnew == NULL)
				goto error;
			rnew->next = NULL;
			if (*rangehead == NULL) {
				*rangehead = rnew;
				r = *rangehead;
			} else {
				r->next = rnew;
				r = r->next;
			}
			rnew->range.low = (uint16_t) strtoul(id,NULL,0);
			rnew->range.high = rnew->range.low;
			free(id);
		}
	}
	r = *rangehead;
	r->omit = omit;
	return 0;
error:
	yyerror("out of memory");
	return -1;
}

/* flip to included ranges */
int avrule_omit_ioctls(struct av_ioctl_range_list **rangehead)
{
	struct av_ioctl_range_list *rnew, *r, *newhead, *r2;

	rnew = calloc(1, sizeof(struct av_ioctl_range_list));
	if (!rnew)
		goto error;

	newhead = rnew;

	r = *rangehead;
	r2 = newhead;

	if (r->range.low == 0) {
		r2->range.low = r->range.high + 1;
		r = r->next;
	} else {
		r2->range.low = 0;
	}

	while (r) {
		r2->range.high = r->range.low - 1;
		rnew = calloc(1, sizeof(struct av_ioctl_range_list));
		if (!rnew)
			goto error;
		r2->next = rnew;
		r2 = r2->next;

		r2->range.low = r->range.high + 1;
		if (!r->next)
			r2->range.high = 0xffff;
		r = r->next;
	}

	r = *rangehead;
	while (r != NULL) {
		r2 = r;
		r = r->next;
		free(r2);
	}
	*rangehead = newhead;
	return 0;

error:
	yyerror("out of memory");
	return -1;
}

int avrule_ioctl_ranges(struct av_ioctl_range_list **rangelist)
{
	struct av_ioctl_range_list *rangehead;
	uint8_t omit;

	/* read in ranges to include and omit */
	if (avrule_read_ioctls(&rangehead))
		return -1;
	omit = rangehead->omit;
	if (rangehead == NULL) {
		yyerror("error processing ioctl commands");
		return -1;
	}
	/* sort and merge the input ioctls */
	if (avrule_sort_ioctls(&rangehead))
		return -1;
	if (avrule_merge_ioctls(&rangehead))
		return -1;
	/* flip ranges if these are ommited*/
	if (omit) {
		if (avrule_omit_ioctls(&rangehead))
			return -1;
	}

	*rangelist = rangehead;
	return 0;
}

int define_te_avtab_xperms_helper(int which, avrule_t ** rule)
{
	char *id;
	class_perm_node_t *perms, *tail = NULL, *cur_perms = NULL;
	class_datum_t *cladatum;
	perm_datum_t *perdatum = NULL;
	ebitmap_t tclasses;
	ebitmap_node_t *node;
	avrule_t *avrule;
	unsigned int i;
	int add = 1, ret = 0;

	avrule = (avrule_t *) malloc(sizeof(avrule_t));
	if (!avrule) {
		yyerror("out of memory");
		ret = -1;
		goto out;
	}
	avrule_init(avrule);
	avrule->specified = which;
	avrule->line = policydb_lineno;
	avrule->source_line = source_lineno;
	avrule->source_filename = strdup(source_file);
	avrule->xperms = NULL;
	if (!avrule->source_filename) {
		yyerror("out of memory");
		return -1;
	}

	while ((id = queue_remove(id_queue))) {
		if (set_types
		    (&avrule->stypes, id, &add,
		     which == AVRULE_XPERMS_NEVERALLOW ? 1 : 0)) {
			ret = -1;
			goto out;
		}
	}
	add = 1;
	while ((id = queue_remove(id_queue))) {
		if (strcmp(id, "self") == 0) {
			free(id);
			if (add == 0) {
				yyerror("-self is not supported");
				ret = -1;
				goto out;
			}
			avrule->flags |= RULE_SELF;
			continue;
		}
		if (set_types
		    (&avrule->ttypes, id, &add,
		     which == AVRULE_XPERMS_NEVERALLOW ? 1 : 0)) {
			ret = -1;
			goto out;
		}
	}

	ebitmap_init(&tclasses);
	ret = read_classes(&tclasses);
	if (ret)
		goto out;

	perms = NULL;
	id = queue_head(id_queue);
	ebitmap_for_each_bit(&tclasses, node, i) {
		if (!ebitmap_node_get_bit(node, i))
			continue;
		cur_perms =
		    (class_perm_node_t *) malloc(sizeof(class_perm_node_t));
		if (!cur_perms) {
			yyerror("out of memory");
			ret = -1;
			goto out;
		}
		class_perm_node_init(cur_perms);
		cur_perms->tclass = i + 1;
		if (!perms)
			perms = cur_perms;
		if (tail)
			tail->next = cur_perms;
		tail = cur_perms;

		cladatum = policydbp->class_val_to_struct[i];
		perdatum = hashtab_search(cladatum->permissions.table, id);
		if (!perdatum) {
			if (cladatum->comdatum) {
				perdatum = hashtab_search(cladatum->comdatum->
							permissions.table,
							id);
			}
		}
		if (!perdatum) {
			yyerror2("permission %s is not defined"
				     " for class %s", id,
				     policydbp->p_class_val_to_name[i]);
			continue;
		} else if (!is_perm_in_scope (id, policydbp->p_class_val_to_name[i])) {
			yyerror2("permission %s of class %s is"
			     " not within scope", id,
			     policydbp->p_class_val_to_name[i]);
			continue;
		} else {
			cur_perms->data |= 1U << (perdatum->s.value - 1);
		}
	}

	ebitmap_destroy(&tclasses);

	avrule->perms = perms;
	*rule = avrule;

out:
	return ret;
}

/* index of the u32 containing the permission */
#define XPERM_IDX(x) (x >> 5)
/* set bits 0 through x-1 within the u32 */
#define XPERM_SETBITS(x) ((1 << (x & 0x1f)) - 1)
/* low value for this u32 */
#define XPERM_LOW(x) (x << 5)
/* high value for this u32 */
#define XPERM_HIGH(x) (((x + 1) << 5) - 1)
void avrule_xperm_setrangebits(uint16_t low, uint16_t high,
				av_extended_perms_t *xperms)
{
	unsigned int i;
	uint16_t h = high + 1;
	/* for each u32 that this low-high range touches, set driver permissions */
	for (i = XPERM_IDX(low); i <= XPERM_IDX(high); i++) {
		/* set all bits in u32 */
		if ((low <= XPERM_LOW(i)) && (high >= XPERM_HIGH(i)))
			xperms->perms[i] |= ~0U;
		/* set low bits */
		else if ((low <= XPERM_LOW(i)) && (high < XPERM_HIGH(i)))
			xperms->perms[i] |= XPERM_SETBITS(h);
		/* set high bits */
		else if ((low > XPERM_LOW(i)) && (high >= XPERM_HIGH(i)))
			xperms->perms[i] |= ~0U - XPERM_SETBITS(low);
		/* set middle bits */
		else if ((low > XPERM_LOW(i)) && (high <= XPERM_HIGH(i)))
			xperms->perms[i] |= XPERM_SETBITS(h) - XPERM_SETBITS(low);
	}
}

int avrule_xperms_used(av_extended_perms_t *xperms)
{
	unsigned int i;

	for (i = 0; i < sizeof(xperms->perms)/sizeof(xperms->perms[0]); i++) {
		if (xperms->perms[i])
			return 1;
	}
	return 0;
}

/*
 * using definitions found in kernel document ioctl-number.txt
 * The kernel components of an ioctl command are:
 * dir, size, driver, and fucntion. Only the driver and function fields
 * are considered here
 */
#define IOC_DRIV(x) (x >> 8)
#define IOC_FUNC(x) (x & 0xff)
#define IOC_CMD(driver, func) ((driver << 8) + func)
int avrule_ioctl_partialdriver(struct av_ioctl_range_list *rangelist,
				av_extended_perms_t *complete_driver,
				av_extended_perms_t **extended_perms)
{
	struct av_ioctl_range_list *r;
	av_extended_perms_t *xperms;
	uint8_t low, high;

	xperms = calloc(1, sizeof(av_extended_perms_t));
	if (!xperms) {
		yyerror("out of memory");
		return - 1;
	}

	r = rangelist;
	while(r) {
		low = IOC_DRIV(r->range.low);
		high = IOC_DRIV(r->range.high);
		if (complete_driver) {
			if (!xperm_test(low, complete_driver->perms))
				xperm_set(low, xperms->perms);
			if (!xperm_test(high, complete_driver->perms))
				xperm_set(high, xperms->perms);
		} else {
			xperm_set(low, xperms->perms);
			xperm_set(high, xperms->perms);
		}
		r = r->next;
	}
	if (avrule_xperms_used(xperms)) {
		*extended_perms = xperms;
	} else {
		free(xperms);
		*extended_perms = NULL;
	}
	return 0;

}

int avrule_ioctl_completedriver(struct av_ioctl_range_list *rangelist,
			av_extended_perms_t **extended_perms)
{
	struct av_ioctl_range_list *r;
	av_extended_perms_t *xperms;
	uint16_t low, high;
	xperms = calloc(1, sizeof(av_extended_perms_t));
	if (!xperms) {
		yyerror("out of memory");
		return - 1;
	}

	r = rangelist;
	while(r) {
		/*
		 * Any driver code that has sequence 0x00 - 0xff is a complete code,
		 *
		 * if command number = 0xff, then round high up to next code,
		 * else 0x00 - 0xfe keep current code
		 * of this range. temporarily u32 for the + 1
		 * to account for possible rollover before right shift
		 */
		high = IOC_DRIV((uint32_t) (r->range.high + 1));
		/* if 0x00 keep current driver code else 0x01 - 0xff round up to next code*/
		low = IOC_DRIV(r->range.low);
		if (IOC_FUNC(r->range.low))
			low++;
		if (high > low)
			avrule_xperm_setrangebits(low, high - 1, xperms);
		r = r->next;
	}
	if (avrule_xperms_used(xperms)) {
		xperms->driver = 0x00;
		xperms->specified = AVRULE_XPERMS_IOCTLDRIVER;
		*extended_perms = xperms;
	} else {
		free(xperms);
		*extended_perms = NULL;
	}
	return 0;
}

int avrule_ioctl_func(struct av_ioctl_range_list *rangelist,
		av_extended_perms_t **extended_perms, unsigned int driver)
{
	struct av_ioctl_range_list *r;
	av_extended_perms_t *xperms;
	uint16_t low, high;

	*extended_perms = NULL;
	xperms = calloc(1, sizeof(av_extended_perms_t));
	if (!xperms) {
		yyerror("out of memory");
		return - 1;
	}

	r = rangelist;
	/* for the passed in driver code, find the ranges that apply */
	while (r) {
		low = r->range.low;
		high = r->range.high;
		if ((driver != IOC_DRIV(low)) && (driver != IOC_DRIV(high))) {
			r = r->next;
			continue;
		}

		if (driver == IOC_DRIV(low)) {
			if (high > IOC_CMD(driver, 0xff))
				high = IOC_CMD(driver, 0xff);

		} else {
			if (low < IOC_CMD(driver, 0))
				low = IOC_CMD(driver, 0);
		}

		low = IOC_FUNC(low);
		high = IOC_FUNC(high);
		avrule_xperm_setrangebits(low, high, xperms);
		xperms->driver = driver;
		xperms->specified = AVRULE_XPERMS_IOCTLFUNCTION;
		r = r->next;
	}

	if (avrule_xperms_used(xperms)) {
		*extended_perms = xperms;
	} else {
		free(xperms);
		*extended_perms = NULL;
	}
	return 0;
}

void avrule_ioctl_freeranges(struct av_ioctl_range_list *rangelist)
{
	struct av_ioctl_range_list *r, *tmp;
	r = rangelist;
	while (r) {
		tmp = r;
		r = r->next;
		free(tmp);
	}
}

unsigned int xperms_for_each_bit(unsigned int *bit, av_extended_perms_t *xperms)
{
	unsigned int i;
	for (i = *bit; i < sizeof(xperms->perms)*8; i++) {
		if (xperm_test(i,xperms->perms)) {
			xperm_clear(i, xperms->perms);
			*bit = i;
			return 1;
		}
	}
	return 0;
}

int avrule_cpy(avrule_t *dest, avrule_t *src)
{
	class_perm_node_t *src_perms;
	class_perm_node_t *dest_perms, *dest_tail;
	dest_tail = NULL;

	avrule_init(dest);
	dest->specified = src->specified;
	dest->flags = src->flags;
	if (type_set_cpy(&dest->stypes, &src->stypes)) {
		yyerror("out of memory");
		return - 1;
	}
	if (type_set_cpy(&dest->ttypes, &src->ttypes)) {
		yyerror("out of memory");
		return - 1;
	}
	dest->line = src->line;
	dest->source_filename = strdup(source_file);
	if (!dest->source_filename) {
		yyerror("out of memory");
		return -1;
	}
	dest->source_line = src->source_line;

	/* increment through the class perms and copy over */
	src_perms = src->perms;
	while (src_perms) {
		dest_perms = (class_perm_node_t *) calloc(1, sizeof(class_perm_node_t));
		class_perm_node_init(dest_perms);
		if (!dest_perms) {
			yyerror("out of memory");
			return -1;
		}
		if (!dest->perms)
			dest->perms = dest_perms;
		else
			dest_tail->next = dest_perms;

		dest_perms->tclass = src_perms->tclass;
		dest_perms->data = src_perms->data;
		dest_perms->next = NULL;
		dest_tail = dest_perms;
		src_perms = src_perms->next;
	}
	return 0;
}

int define_te_avtab_ioctl(avrule_t *avrule_template)
{
	avrule_t *avrule;
	struct av_ioctl_range_list *rangelist;
	av_extended_perms_t *complete_driver, *partial_driver, *xperms;
	unsigned int i;


	/* organize ioctl ranges */
	if (avrule_ioctl_ranges(&rangelist))
		return -1;

	/* create rule for ioctl driver types that are entirely enabled */
	if (avrule_ioctl_completedriver(rangelist, &complete_driver))
		return -1;
	if (complete_driver) {
		avrule = (avrule_t *) calloc(1, sizeof(avrule_t));
		if (!avrule) {
			yyerror("out of memory");
			return -1;
		}
		if (avrule_cpy(avrule, avrule_template))
			return -1;
		avrule->xperms = complete_driver;
		append_avrule(avrule);
	}

	/* flag ioctl driver codes that are partially enabled */
	if (avrule_ioctl_partialdriver(rangelist, complete_driver, &partial_driver))
		return -1;

	if (!partial_driver || !avrule_xperms_used(partial_driver))
		goto done;

	/*
	 * create rule for each partially used driver codes
	 * "partially used" meaning that the code number e.g. socket 0x89
	 * has some permission bits set and others not set.
	 */
	i = 0;
	while (xperms_for_each_bit(&i, partial_driver)) {
		if (avrule_ioctl_func(rangelist, &xperms, i))
			return -1;

		if (xperms) {
			avrule = (avrule_t *) calloc(1, sizeof(avrule_t));
			if (!avrule) {
				yyerror("out of memory");
				return -1;
			}
			if (avrule_cpy(avrule, avrule_template))
				return -1;
			avrule->xperms = xperms;
			append_avrule(avrule);
		}
	}

done:
	if (partial_driver)
		free(partial_driver);

	return 0;
}

int define_te_avtab_extended_perms(int which)
{
	char *id;
	unsigned int i;
	avrule_t *avrule_template;

	if (pass == 1) {
		for (i = 0; i < 4; i++) {
			while ((id = queue_remove(id_queue)))
				free(id);
		}
		return 0;
	}

	/* populate avrule template with source/target/tclass */
	if (define_te_avtab_xperms_helper(which, &avrule_template))
		return -1;

	id = queue_remove(id_queue);
	if (strcmp(id,"ioctl") == 0) {
		free(id);
		if (define_te_avtab_ioctl(avrule_template))
			return -1;
	} else {
		yyerror("only ioctl extended permissions are supported");
		free(id);
		return -1;
	}
	return 0;
}

int define_te_avtab_helper(int which, avrule_t ** rule)
{
	char *id;
	class_datum_t *cladatum;
	perm_datum_t *perdatum = NULL;
	class_perm_node_t *perms, *tail = NULL, *cur_perms = NULL;
	ebitmap_t tclasses;
	ebitmap_node_t *node;
	avrule_t *avrule;
	unsigned int i;
	int add = 1, ret = 0;
	int suppress = 0;

	avrule = (avrule_t *) malloc(sizeof(avrule_t));
	if (!avrule) {
		yyerror("memory error");
		ret = -1;
		goto out;
	}
	avrule_init(avrule);
	avrule->specified = which;
	avrule->line = policydb_lineno;
	avrule->source_line = source_lineno;
	avrule->source_filename = strdup(source_file);
	avrule->xperms = NULL;
	if (!avrule->source_filename) {
		yyerror("out of memory");
		return -1;
	}


	while ((id = queue_remove(id_queue))) {
		if (set_types
		    (&avrule->stypes, id, &add,
		     which == AVRULE_NEVERALLOW ? 1 : 0)) {
			ret = -1;
			goto out;
		}
	}
	add = 1;
	while ((id = queue_remove(id_queue))) {
		if (strcmp(id, "self") == 0) {
			free(id);
			if (add == 0) {
				yyerror("-self is not supported");
				ret = -1;
				goto out;
			}
			avrule->flags |= RULE_SELF;
			continue;
		}
		if (set_types
		    (&avrule->ttypes, id, &add,
		     which == AVRULE_NEVERALLOW ? 1 : 0)) {
			ret = -1;
			goto out;
		}
	}

	ebitmap_init(&tclasses);
	ret = read_classes(&tclasses);
	if (ret)
		goto out;

	perms = NULL;
	ebitmap_for_each_bit(&tclasses, node, i) {
		if (!ebitmap_node_get_bit(node, i))
			continue;
		cur_perms =
		    (class_perm_node_t *) malloc(sizeof(class_perm_node_t));
		if (!cur_perms) {
			yyerror("out of memory");
			ret = -1;
			goto out;
		}
		class_perm_node_init(cur_perms);
		cur_perms->tclass = i + 1;
		if (!perms)
			perms = cur_perms;
		if (tail)
			tail->next = cur_perms;
		tail = cur_perms;
	}

	while ((id = queue_remove(id_queue))) {
		cur_perms = perms;
		ebitmap_for_each_bit(&tclasses, node, i) {
			if (!ebitmap_node_get_bit(node, i))
				continue;
			cladatum = policydbp->class_val_to_struct[i];

			if (strcmp(id, "*") == 0) {
				/* set all permissions in the class */
				cur_perms->data = ~0U;
				goto next;
			}

			if (strcmp(id, "~") == 0) {
				/* complement the set */
				if (which == AVRULE_DONTAUDIT)
					yywarn("dontaudit rule with a ~?");
				cur_perms->data = ~cur_perms->data;
				goto next;
			}

			perdatum =
			    hashtab_search(cladatum->permissions.table, id);
			if (!perdatum) {
				if (cladatum->comdatum) {
					perdatum =
					    hashtab_search(cladatum->comdatum->
							   permissions.table,
							   id);
				}
			}
			if (!perdatum) {
				if (!suppress)
					yyerror2("permission %s is not defined"
					     " for class %s", id,
					     policydbp->p_class_val_to_name[i]);
				continue;
			} else
			    if (!is_perm_in_scope
				(id, policydbp->p_class_val_to_name[i])) {
				if (!suppress) {
					yyerror2("permission %s of class %s is"
					     " not within scope", id,
					     policydbp->p_class_val_to_name[i]);
				}
				continue;
			} else {
				cur_perms->data |= 1U << (perdatum->s.value - 1);
			}
		      next:
			cur_perms = cur_perms->next;
		}

		free(id);
	}

	ebitmap_destroy(&tclasses);

	avrule->perms = perms;
	*rule = avrule;

      out:
	if (ret) {
		avrule_destroy(avrule);
		free(avrule);
	}
	return ret;

}

avrule_t *define_cond_te_avtab(int which)
{
	char *id;
	avrule_t *avrule;
	int i;

	if (pass == 1) {
		for (i = 0; i < 4; i++) {
			while ((id = queue_remove(id_queue)))
				free(id);
		}
		return (avrule_t *) 1;	/* any non-NULL value */
	}

	if (define_te_avtab_helper(which, &avrule))
		return COND_ERR;

	return avrule;
}

int define_te_avtab(int which)
{
	char *id;
	avrule_t *avrule;
	int i;

	if (pass == 1) {
		for (i = 0; i < 4; i++) {
			while ((id = queue_remove(id_queue)))
				free(id);
		}
		return 0;
	}

	if (define_te_avtab_helper(which, &avrule))
		return -1;

	/* append this avrule to the end of the current rules list */
	append_avrule(avrule);
	return 0;
}

/* The role-types rule is no longer used to declare regular role or
 * role attribute, but solely aimed for declaring role-types associations.
 */
int define_role_types(void)
{
	role_datum_t *role;
	char *id;
	int add = 1;

	if (pass == 1) {
		while ((id = queue_remove(id_queue)))
			free(id);
		return 0;
	}

	id = (char *)queue_remove(id_queue);
	if (!id) {
		yyerror("no role name for role-types rule?");
		return -1;
	}

	if (!is_id_in_scope(SYM_ROLES, id)) {
		yyerror2("role %s is not within scope", id);
		free(id);
		return -1;
	}

	role = hashtab_search(policydbp->p_roles.table, id);
	if (!role) {
		yyerror2("unknown role %s", id);
		free(id);
		return -1;
	}
	role = get_local_role(id, role->s.value, (role->flavor == ROLE_ATTRIB));

	while ((id = queue_remove(id_queue))) {
		if (set_types(&role->types, id, &add, 0))
			return -1;
	}

	return 0;
}

int define_attrib_role(void)
{
	if (pass == 2) {
		free(queue_remove(id_queue));
		return 0;
	}

	/* Declare a role attribute */
	if (declare_role(TRUE) == NULL)
		return -1;

	return 0;
}

int define_role_attr(void)
{
	char *id;
	role_datum_t *r, *attr;

	if (pass == 2) {
		while ((id = queue_remove(id_queue)))
			free(id);
		return 0;
	}
	
	/* Declare a regular role */
	if ((r = declare_role(FALSE)) == NULL)
		return -1;

	while ((id = queue_remove(id_queue))) {
		if (!is_id_in_scope(SYM_ROLES, id)) {
			yyerror2("attribute %s is not within scope", id);
			free(id);
			return -1;
		}
		attr = hashtab_search(policydbp->p_roles.table, id);
		if (!attr) {
			/* treat it as a fatal error */
			yyerror2("role attribute %s is not declared", id);
			free(id);
			return -1;
		}

		if (attr->flavor != ROLE_ATTRIB) {
			yyerror2("%s is a regular role, not an attribute", id);
			free(id);
			return -1;
		}

		if ((attr = get_local_role(id, attr->s.value, 1)) == NULL) {
			yyerror("Out of memory!");
			return -1;
		}

		if (ebitmap_set_bit(&attr->roles, (r->s.value - 1), TRUE)) {
			yyerror("out of memory");
			return -1;
		}
	}

	return 0;
}

int define_roleattribute(void)
{
	char *id;
	role_datum_t *r, *attr;

	if (pass == 2) {
		while ((id = queue_remove(id_queue)))
			free(id);
		return 0;
	}

	id = (char *)queue_remove(id_queue);
	if (!id) {
		yyerror("no role name for roleattribute definition?");
		return -1;
	}

	if (!is_id_in_scope(SYM_ROLES, id)) {
		yyerror2("role %s is not within scope", id);
		free(id);
		return -1;
	}
	r = hashtab_search(policydbp->p_roles.table, id);
	/* We support adding one role attribute into another */
	if (!r) {
		yyerror2("unknown role %s", id);
		free(id);
		return -1;
	}
	free(id);

	while ((id = queue_remove(id_queue))) {
		if (!is_id_in_scope(SYM_ROLES, id)) {
			yyerror2("attribute %s is not within scope", id);
			free(id);
			return -1;
		}
		attr = hashtab_search(policydbp->p_roles.table, id);
		if (!attr) {
			/* treat it as a fatal error */
			yyerror2("role attribute %s is not declared", id);
			free(id);
			return -1;
		}

		if (attr->flavor != ROLE_ATTRIB) {
			yyerror2("%s is a regular role, not an attribute", id);
			free(id);
			return -1;
		}

		if ((attr = get_local_role(id, attr->s.value, 1)) == NULL) {
			yyerror("Out of memory!");
			return -1;
		}

		if (ebitmap_set_bit(&attr->roles, (r->s.value - 1), TRUE)) {
			yyerror("out of memory");
			return -1;
		}
	}

	return 0;
}

role_datum_t *merge_roles_dom(role_datum_t * r1, role_datum_t * r2)
{
	role_datum_t *new;

	if (pass == 1) {
		return (role_datum_t *) 1;	/* any non-NULL value */
	}

	new = malloc(sizeof(role_datum_t));
	if (!new) {
		yyerror("out of memory");
		return NULL;
	}
	memset(new, 0, sizeof(role_datum_t));
	new->s.value = 0;		/* temporary role */
	if (ebitmap_or(&new->dominates, &r1->dominates, &r2->dominates)) {
		yyerror("out of memory");
		free(new);
		return NULL;
	}
	if (ebitmap_or(&new->types.types, &r1->types.types, &r2->types.types)) {
		yyerror("out of memory");
		free(new);
		return NULL;
	}
	if (!r1->s.value) {
		/* free intermediate result */
		type_set_destroy(&r1->types);
		ebitmap_destroy(&r1->dominates);
		free(r1);
	}
	if (!r2->s.value) {
		/* free intermediate result */
		yyerror("right hand role is temporary?");
		type_set_destroy(&r2->types);
		ebitmap_destroy(&r2->dominates);
		free(r2);
	}
	return new;
}

/* This function eliminates the ordering dependency of role dominance rule */
static int dominate_role_recheck(hashtab_key_t key __attribute__ ((unused)),
				 hashtab_datum_t datum, void *arg)
{
	role_datum_t *rdp = (role_datum_t *) arg;
	role_datum_t *rdatum = (role_datum_t *) datum;
	ebitmap_node_t *node;
	uint32_t i;

	/* Don't bother to process against self role */
	if (rdatum->s.value == rdp->s.value)
		return 0;

	/* If a dominating role found */
	if (ebitmap_get_bit(&(rdatum->dominates), rdp->s.value - 1)) {
		ebitmap_t types;
		ebitmap_init(&types);
		if (type_set_expand(&rdp->types, &types, policydbp, 1)) {
			ebitmap_destroy(&types);
			return -1;
		}
		/* raise types and dominates from dominated role */
		ebitmap_for_each_bit(&rdp->dominates, node, i) {
			if (ebitmap_node_get_bit(node, i))
				if (ebitmap_set_bit
				    (&rdatum->dominates, i, TRUE))
					goto oom;
		}
		ebitmap_for_each_bit(&types, node, i) {
			if (ebitmap_node_get_bit(node, i))
				if (ebitmap_set_bit
				    (&rdatum->types.types, i, TRUE))
					goto oom;
		}
		ebitmap_destroy(&types);
	}

	/* go through all the roles */
	return 0;
      oom:
	yyerror("Out of memory");
	return -1;
}

role_datum_t *define_role_dom(role_datum_t * r)
{
	role_datum_t *role;
	char *role_id;
	ebitmap_node_t *node;
	unsigned int i;
	int ret;

	if (pass == 1) {
		role_id = queue_remove(id_queue);
		free(role_id);
		return (role_datum_t *) 1;	/* any non-NULL value */
	}

	yywarn("Role dominance has been deprecated");

	role_id = queue_remove(id_queue);
	if (!is_id_in_scope(SYM_ROLES, role_id)) {
		yyerror2("role %s is not within scope", role_id);
		free(role_id);
		return NULL;
	}
	role = (role_datum_t *) hashtab_search(policydbp->p_roles.table,
					       role_id);
	if (!role) {
		role = (role_datum_t *) malloc(sizeof(role_datum_t));
		if (!role) {
			yyerror("out of memory");
			free(role_id);
			return NULL;
		}
		memset(role, 0, sizeof(role_datum_t));
		ret =
		    declare_symbol(SYM_ROLES, (hashtab_key_t) role_id,
				   (hashtab_datum_t) role, &role->s.value,
				   &role->s.value);
		switch (ret) {
		case -3:{
				yyerror("Out of memory!");
				goto cleanup;
			}
		case -2:{
				yyerror2("duplicate declaration of role %s",
					 role_id);
				goto cleanup;
			}
		case -1:{
				yyerror("could not declare role here");
				goto cleanup;
			}
		case 0:
		case 1:{
				break;
			}
		default:{
				assert(0);	/* should never get here */
			}
		}
		if (ebitmap_set_bit(&role->dominates, role->s.value - 1, TRUE)) {
			yyerror("Out of memory!");
			goto cleanup;
		}
	}
	if (r) {
		ebitmap_t types;
		ebitmap_init(&types);
		ebitmap_for_each_bit(&r->dominates, node, i) {
			if (ebitmap_node_get_bit(node, i))
				if (ebitmap_set_bit(&role->dominates, i, TRUE))
					goto oom;
		}
		if (type_set_expand(&r->types, &types, policydbp, 1)) {
			ebitmap_destroy(&types);
			return NULL;
		}
		ebitmap_for_each_bit(&types, node, i) {
			if (ebitmap_node_get_bit(node, i))
				if (ebitmap_set_bit
				    (&role->types.types, i, TRUE))
					goto oom;
		}
		ebitmap_destroy(&types);
		if (!r->s.value) {
			/* free intermediate result */
			type_set_destroy(&r->types);
			ebitmap_destroy(&r->dominates);
			free(r);
		}
		/*
		 * Now go through all the roles and escalate this role's
		 * dominates and types if a role dominates this role.
		 */
		hashtab_map(policydbp->p_roles.table,
			    dominate_role_recheck, role);
	}
	return role;
      cleanup:
	free(role_id);
	role_datum_destroy(role);
	free(role);
	return NULL;
      oom:
	yyerror("Out of memory");
	goto cleanup;
}

static int role_val_to_name_helper(hashtab_key_t key, hashtab_datum_t datum,
				   void *p)
{
	struct val_to_name *v = p;
	role_datum_t *roldatum;

	roldatum = (role_datum_t *) datum;

	if (v->val == roldatum->s.value) {
		v->name = key;
		return 1;
	}

	return 0;
}

static char *role_val_to_name(unsigned int val)
{
	struct val_to_name v;
	int rc;

	v.val = val;
	rc = hashtab_map(policydbp->p_roles.table, role_val_to_name_helper, &v);
	if (rc)
		return v.name;
	return NULL;
}

static int set_roles(role_set_t * set, char *id)
{
	role_datum_t *r;

	if (strcmp(id, "*") == 0) {
		free(id);
		yyerror("* is not allowed for role sets");
		return -1;
	}

	if (strcmp(id, "~") == 0) {
		free(id);
		yyerror("~ is not allowed for role sets");
		return -1;
	}
	if (!is_id_in_scope(SYM_ROLES, id)) {
		yyerror2("role %s is not within scope", id);
		free(id);
		return -1;
	}
	r = hashtab_search(policydbp->p_roles.table, id);
	if (!r) {
		yyerror2("unknown role %s", id);
		free(id);
		return -1;
	}

	if (ebitmap_set_bit(&set->roles, r->s.value - 1, TRUE)) {
		yyerror("out of memory");
		free(id);
		return -1;
	}
	free(id);
	return 0;
}

int define_role_trans(int class_specified)
{
	char *id;
	role_datum_t *role;
	role_set_t roles;
	type_set_t types;
	class_datum_t *cladatum;
	ebitmap_t e_types, e_roles, e_classes;
	ebitmap_node_t *tnode, *rnode, *cnode;
	struct role_trans *tr = NULL;
	struct role_trans_rule *rule = NULL;
	unsigned int i, j, k;
	int add = 1;

	if (pass == 1) {
		while ((id = queue_remove(id_queue)))
			free(id);
		while ((id = queue_remove(id_queue)))
			free(id);
		if (class_specified)
			while ((id = queue_remove(id_queue)))
				free(id);
		id = queue_remove(id_queue);
		free(id);
		return 0;
	}

	role_set_init(&roles);
	ebitmap_init(&e_roles);
	type_set_init(&types);
	ebitmap_init(&e_types);
	ebitmap_init(&e_classes);

	while ((id = queue_remove(id_queue))) {
		if (set_roles(&roles, id))
			return -1;
	}
	add = 1;
	while ((id = queue_remove(id_queue))) {
		if (set_types(&types, id, &add, 0))
			return -1;
	}

	if (class_specified) {
		if (read_classes(&e_classes))
			return -1;
	} else {
		cladatum = hashtab_search(policydbp->p_classes.table,
					  "process");
		if (!cladatum) {
			yyerror2("could not find process class for "
				 "legacy role_transition statement");
			return -1;
		}

		if (ebitmap_set_bit(&e_classes, cladatum->s.value - 1, TRUE)) {
			yyerror("out of memory");
			return -1;
		}
	}

	id = (char *)queue_remove(id_queue);
	if (!id) {
		yyerror("no new role in transition definition?");
		goto bad;
	}
	if (!is_id_in_scope(SYM_ROLES, id)) {
		yyerror2("role %s is not within scope", id);
		free(id);
		goto bad;
	}
	role = hashtab_search(policydbp->p_roles.table, id);
	if (!role) {
		yyerror2("unknown role %s used in transition definition", id);
		free(id);
		goto bad;
	}

	if (role->flavor != ROLE_ROLE) {
		yyerror2("the new role %s must be a regular role", id);
		free(id);
		goto bad;
	}
	free(id);

	/* This ebitmap business is just to ensure that there are not conflicting role_trans rules */
	if (role_set_expand(&roles, &e_roles, policydbp, NULL, NULL))
		goto bad;

	if (type_set_expand(&types, &e_types, policydbp, 1))
		goto bad;

	ebitmap_for_each_bit(&e_roles, rnode, i) {
		if (!ebitmap_node_get_bit(rnode, i))
			continue;
		ebitmap_for_each_bit(&e_types, tnode, j) {
			if (!ebitmap_node_get_bit(tnode, j))
				continue;
			ebitmap_for_each_bit(&e_classes, cnode, k) {
				if (!ebitmap_node_get_bit(cnode, k))
					continue;
				for (tr = policydbp->role_tr; tr;
				     tr = tr->next) {
					if (tr->role == (i + 1) &&
					    tr->type == (j + 1) &&
					    tr->tclass == (k + 1)) {
						yyerror2("duplicate role "
							 "transition for "
							 "(%s,%s,%s)",
							 role_val_to_name(i+1),
							 policydbp->p_type_val_to_name[j],
							 policydbp->p_class_val_to_name[k]);
						goto bad;
					}
				}

				tr = malloc(sizeof(struct role_trans));
				if (!tr) {
					yyerror("out of memory");
					return -1;
				}
				memset(tr, 0, sizeof(struct role_trans));
				tr->role = i + 1;
				tr->type = j + 1;
				tr->tclass = k + 1;
				tr->new_role = role->s.value;
				tr->next = policydbp->role_tr;
				policydbp->role_tr = tr;
			}
		}
	}
	/* Now add the real rule */
	rule = malloc(sizeof(struct role_trans_rule));
	if (!rule) {
		yyerror("out of memory");
		return -1;
	}
	memset(rule, 0, sizeof(struct role_trans_rule));
	rule->roles = roles;
	rule->types = types;
	rule->classes = e_classes;
	rule->new_role = role->s.value;

	append_role_trans(rule);

	ebitmap_destroy(&e_roles);
	ebitmap_destroy(&e_types);

	return 0;

      bad:
	return -1;
}

int define_role_allow(void)
{
	char *id;
	struct role_allow_rule *ra = 0;

	if (pass == 1) {
		while ((id = queue_remove(id_queue)))
			free(id);
		while ((id = queue_remove(id_queue)))
			free(id);
		return 0;
	}

	ra = malloc(sizeof(role_allow_rule_t));
	if (!ra) {
		yyerror("out of memory");
		return -1;
	}
	role_allow_rule_init(ra);

	while ((id = queue_remove(id_queue))) {
		if (set_roles(&ra->roles, id)) {
			free(ra);
			return -1;
		}
	}

	while ((id = queue_remove(id_queue))) {
		if (set_roles(&ra->new_roles, id)) {
			free(ra);
			return -1;
		}
	}

	append_role_allow(ra);
	return 0;
}

avrule_t *define_cond_filename_trans(void)
{
	yyerror("type transitions with a filename not allowed inside "
		"conditionals\n");
	return COND_ERR;
}

int define_filename_trans(void)
{
	char *id, *name = NULL;
	type_set_t stypes, ttypes;
	ebitmap_t e_stypes, e_ttypes;
	ebitmap_t e_tclasses;
	ebitmap_node_t *snode, *tnode, *cnode;
	filename_trans_t *ft;
	filename_trans_datum_t *ftdatum;
	filename_trans_rule_t *ftr;
	type_datum_t *typdatum;
	uint32_t otype;
	unsigned int c, s, t;
	int add, rc;

	if (pass == 1) {
		/* stype */
		while ((id = queue_remove(id_queue)))
			free(id);
		/* ttype */
		while ((id = queue_remove(id_queue)))
			free(id);
		/* tclass */
		while ((id = queue_remove(id_queue)))
			free(id);
		/* otype */
		id = queue_remove(id_queue);
		free(id);
		/* name */
		id = queue_remove(id_queue);
		free(id);
		return 0;
	}

	type_set_init(&stypes);
	type_set_init(&ttypes);
	ebitmap_init(&e_stypes);
	ebitmap_init(&e_ttypes);
	ebitmap_init(&e_tclasses);

	add = 1;
	while ((id = queue_remove(id_queue))) {
		if (set_types(&stypes, id, &add, 0))
			goto bad;
	}

	add =1;
	while ((id = queue_remove(id_queue))) {
		if (set_types(&ttypes, id, &add, 0))
			goto bad;
	}

	if (read_classes(&e_tclasses))
		goto bad;

	id = (char *)queue_remove(id_queue);
	if (!id) {
		yyerror("no otype in transition definition?");
		goto bad;
	}
	if (!is_id_in_scope(SYM_TYPES, id)) {
		yyerror2("type %s is not within scope", id);
		free(id);
		goto bad;
	}
	typdatum = hashtab_search(policydbp->p_types.table, id);
	if (!typdatum) {
		yyerror2("unknown type %s used in transition definition", id);
		free(id);
		goto bad;
	}
	free(id);
	otype = typdatum->s.value;

	name = queue_remove(id_queue);
	if (!name) {
		yyerror("no pathname specified in filename_trans definition?");
		goto bad;
	}

	/* We expand the class set into seperate rules.  We expand the types
	 * just to make sure there are not duplicates.  They will get turned
	 * into seperate rules later */
	if (type_set_expand(&stypes, &e_stypes, policydbp, 1))
		goto bad;

	if (type_set_expand(&ttypes, &e_ttypes, policydbp, 1))
		goto bad;

	ebitmap_for_each_bit(&e_tclasses, cnode, c) {
		if (!ebitmap_node_get_bit(cnode, c))
			continue;
		ebitmap_for_each_bit(&e_stypes, snode, s) {
			if (!ebitmap_node_get_bit(snode, s))
				continue;
			ebitmap_for_each_bit(&e_ttypes, tnode, t) {
				if (!ebitmap_node_get_bit(tnode, t))
					continue;

				ft = calloc(1, sizeof(*ft));
				if (!ft) {
					yyerror("out of memory");
					goto bad;
				}
				ft->stype = s+1;
				ft->ttype = t+1;
				ft->tclass = c+1;
				ft->name = strdup(name);
				if (!ft->name) {
					yyerror("out of memory");
					goto bad;
				}

				ftdatum = hashtab_search(policydbp->filename_trans,
							 (hashtab_key_t)ft);
				if (ftdatum) {
					yyerror2("duplicate filename transition for: filename_trans %s %s %s:%s",
						 name,
						 policydbp->p_type_val_to_name[s],
						 policydbp->p_type_val_to_name[t],
						 policydbp->p_class_val_to_name[c]);
					goto bad;
				}

				ftdatum = calloc(1, sizeof(*ftdatum));
				if (!ftdatum) {
					yyerror("out of memory");
					goto bad;
				}
				rc = hashtab_insert(policydbp->filename_trans,
						    (hashtab_key_t)ft,
						    ftdatum);
				if (rc) {
					yyerror("out of memory");
					goto bad;
				}
			}
		}
	
		/* Now add the real rule since we didn't find any duplicates */
		ftr = malloc(sizeof(*ftr));
		if (!ftr) {
			yyerror("out of memory");
			goto bad;
		}
		filename_trans_rule_init(ftr);
		append_filename_trans(ftr);

		ftr->name = strdup(name);
		if (type_set_cpy(&ftr->stypes, &stypes)) {
			yyerror("out of memory");
			goto bad;
		}
		if (type_set_cpy(&ftr->ttypes, &ttypes)) {
			yyerror("out of memory");
			goto bad;
		}
		ftr->tclass = c + 1;
		ftr->otype = otype;
	}

	free(name);
	ebitmap_destroy(&e_stypes);
	ebitmap_destroy(&e_ttypes);
	ebitmap_destroy(&e_tclasses);
	type_set_destroy(&stypes);
	type_set_destroy(&ttypes);

	return 0;

bad:
	free(name);
	ebitmap_destroy(&e_stypes);
	ebitmap_destroy(&e_ttypes);
	ebitmap_destroy(&e_tclasses);
	type_set_destroy(&stypes);
	type_set_destroy(&ttypes);
	return -1;
}

static constraint_expr_t *constraint_expr_clone(constraint_expr_t * expr)
{
	constraint_expr_t *h = NULL, *l = NULL, *e, *newe;
	for (e = expr; e; e = e->next) {
		newe = malloc(sizeof(*newe));
		if (!newe)
			goto oom;
		if (constraint_expr_init(newe) == -1) {
			free(newe);
			goto oom;
		}
		if (l)
			l->next = newe;
		else
			h = newe;
		l = newe;
		newe->expr_type = e->expr_type;
		newe->attr = e->attr;
		newe->op = e->op;
		if (newe->expr_type == CEXPR_NAMES) {
			if (newe->attr & CEXPR_TYPE) {
				if (type_set_cpy
				    (newe->type_names, e->type_names))
					goto oom;
			} else {
				if (ebitmap_cpy(&newe->names, &e->names))
					goto oom;
			}
		}
	}

	return h;
      oom:
	e = h;
	while (e) {
		l = e;
		e = e->next;
		constraint_expr_destroy(l);
	}
	return NULL;
}

int define_constraint(constraint_expr_t * expr)
{
	struct constraint_node *node;
	char *id;
	class_datum_t *cladatum;
	perm_datum_t *perdatum;
	ebitmap_t classmap;
	ebitmap_node_t *enode;
	constraint_expr_t *e;
	unsigned int i;
	int depth;
	unsigned char useexpr = 1;

	if (pass == 1) {
		while ((id = queue_remove(id_queue)))
			free(id);
		while ((id = queue_remove(id_queue)))
			free(id);
		return 0;
	}

	depth = -1;
	for (e = expr; e; e = e->next) {
		switch (e->expr_type) {
		case CEXPR_NOT:
			if (depth < 0) {
				yyerror("illegal constraint expression");
				return -1;
			}
			break;
		case CEXPR_AND:
		case CEXPR_OR:
			if (depth < 1) {
				yyerror("illegal constraint expression");
				return -1;
			}
			depth--;
			break;
		case CEXPR_ATTR:
		case CEXPR_NAMES:
			if (e->attr & CEXPR_XTARGET) {
				yyerror("illegal constraint expression");
				return -1;	/* only for validatetrans rules */
			}
			if (depth == (CEXPR_MAXDEPTH - 1)) {
				yyerror("constraint expression is too deep");
				return -1;
			}
			depth++;
			break;
		default:
			yyerror("illegal constraint expression");
			return -1;
		}
	}
	if (depth != 0) {
		yyerror("illegal constraint expression");
		return -1;
	}

	ebitmap_init(&classmap);
	while ((id = queue_remove(id_queue))) {
		if (!is_id_in_scope(SYM_CLASSES, id)) {
			yyerror2("class %s is not within scope", id);
			free(id);
			return -1;
		}
		cladatum =
		    (class_datum_t *) hashtab_search(policydbp->p_classes.table,
						     (hashtab_key_t) id);
		if (!cladatum) {
			yyerror2("class %s is not defined", id);
			ebitmap_destroy(&classmap);
			free(id);
			return -1;
		}
		if (ebitmap_set_bit(&classmap, cladatum->s.value - 1, TRUE)) {
			yyerror("out of memory");
			ebitmap_destroy(&classmap);
			free(id);
			return -1;
		}
		node = malloc(sizeof(struct constraint_node));
		if (!node) {
			yyerror("out of memory");
			free(node);
			return -1;
		}
		memset(node, 0, sizeof(constraint_node_t));
		if (useexpr) {
			node->expr = expr;
			useexpr = 0;
		} else {
			node->expr = constraint_expr_clone(expr);
		}
		if (!node->expr) {
			yyerror("out of memory");
			free(node);
			return -1;
		}
		node->permissions = 0;

		node->next = cladatum->constraints;
		cladatum->constraints = node;

		free(id);
	}

	while ((id = queue_remove(id_queue))) {
		ebitmap_for_each_bit(&classmap, enode, i) {
			if (ebitmap_node_get_bit(enode, i)) {
				cladatum = policydbp->class_val_to_struct[i];
				node = cladatum->constraints;

				perdatum =
				    (perm_datum_t *) hashtab_search(cladatum->
								    permissions.
								    table,
								    (hashtab_key_t)
								    id);
				if (!perdatum) {
					if (cladatum->comdatum) {
						perdatum =
						    (perm_datum_t *)
						    hashtab_search(cladatum->
								   comdatum->
								   permissions.
								   table,
								   (hashtab_key_t)
								   id);
					}
					if (!perdatum) {
						yyerror2("permission %s is not"
							 " defined", id);
						free(id);
						ebitmap_destroy(&classmap);
						return -1;
					}
				}
				node->permissions |=
				    (1 << (perdatum->s.value - 1));
			}
		}
		free(id);
	}

	ebitmap_destroy(&classmap);

	return 0;
}

int define_validatetrans(constraint_expr_t * expr)
{
	struct constraint_node *node;
	char *id;
	class_datum_t *cladatum;
	ebitmap_t classmap;
	constraint_expr_t *e;
	int depth;
	unsigned char useexpr = 1;

	if (pass == 1) {
		while ((id = queue_remove(id_queue)))
			free(id);
		return 0;
	}

	depth = -1;
	for (e = expr; e; e = e->next) {
		switch (e->expr_type) {
		case CEXPR_NOT:
			if (depth < 0) {
				yyerror("illegal validatetrans expression");
				return -1;
			}
			break;
		case CEXPR_AND:
		case CEXPR_OR:
			if (depth < 1) {
				yyerror("illegal validatetrans expression");
				return -1;
			}
			depth--;
			break;
		case CEXPR_ATTR:
		case CEXPR_NAMES:
			if (depth == (CEXPR_MAXDEPTH - 1)) {
				yyerror("validatetrans expression is too deep");
				return -1;
			}
			depth++;
			break;
		default:
			yyerror("illegal validatetrans expression");
			return -1;
		}
	}
	if (depth != 0) {
		yyerror("illegal validatetrans expression");
		return -1;
	}

	ebitmap_init(&classmap);
	while ((id = queue_remove(id_queue))) {
		if (!is_id_in_scope(SYM_CLASSES, id)) {
			yyerror2("class %s is not within scope", id);
			free(id);
			return -1;
		}
		cladatum =
		    (class_datum_t *) hashtab_search(policydbp->p_classes.table,
						     (hashtab_key_t) id);
		if (!cladatum) {
			yyerror2("class %s is not defined", id);
			ebitmap_destroy(&classmap);
			free(id);
			return -1;
		}
		if (ebitmap_set_bit(&classmap, (cladatum->s.value - 1), TRUE)) {
			yyerror("out of memory");
			ebitmap_destroy(&classmap);
			free(id);
			return -1;
		}

		node = malloc(sizeof(struct constraint_node));
		if (!node) {
			yyerror("out of memory");
			return -1;
		}
		memset(node, 0, sizeof(constraint_node_t));
		if (useexpr) {
			node->expr = expr;
			useexpr = 0;
		} else {
			node->expr = constraint_expr_clone(expr);
		}
		node->permissions = 0;

		node->next = cladatum->validatetrans;
		cladatum->validatetrans = node;

		free(id);
	}

	ebitmap_destroy(&classmap);

	return 0;
}

uintptr_t define_cexpr(uint32_t expr_type, uintptr_t arg1, uintptr_t arg2)
{
	struct constraint_expr *expr, *e1 = NULL, *e2;
	user_datum_t *user;
	role_datum_t *role;
	ebitmap_t negset;
	char *id;
	uint32_t val;
	int add = 1;

	if (pass == 1) {
		if (expr_type == CEXPR_NAMES) {
			while ((id = queue_remove(id_queue)))
				free(id);
		}
		return 1;	/* any non-NULL value */
	}

	if ((expr = malloc(sizeof(*expr))) == NULL ||
	    constraint_expr_init(expr) == -1) {
		yyerror("out of memory");
		free(expr);
		return 0;
	}
	expr->expr_type = expr_type;

	switch (expr_type) {
	case CEXPR_NOT:
		e1 = NULL;
		e2 = (struct constraint_expr *)arg1;
		while (e2) {
			e1 = e2;
			e2 = e2->next;
		}
		if (!e1 || e1->next) {
			yyerror("illegal constraint expression");
			constraint_expr_destroy(expr);
			return 0;
		}
		e1->next = expr;
		return arg1;
	case CEXPR_AND:
	case CEXPR_OR:
		e1 = NULL;
		e2 = (struct constraint_expr *)arg1;
		while (e2) {
			e1 = e2;
			e2 = e2->next;
		}
		if (!e1 || e1->next) {
			yyerror("illegal constraint expression");
			constraint_expr_destroy(expr);
			return 0;
		}
		e1->next = (struct constraint_expr *)arg2;

		e1 = NULL;
		e2 = (struct constraint_expr *)arg2;
		while (e2) {
			e1 = e2;
			e2 = e2->next;
		}
		if (!e1 || e1->next) {
			yyerror("illegal constraint expression");
			constraint_expr_destroy(expr);
			return 0;
		}
		e1->next = expr;
		return arg1;
	case CEXPR_ATTR:
		expr->attr = arg1;
		expr->op = arg2;
		return (uintptr_t) expr;
	case CEXPR_NAMES:
		add = 1;
		expr->attr = arg1;
		expr->op = arg2;
		ebitmap_init(&negset);
		while ((id = (char *)queue_remove(id_queue))) {
			if (expr->attr & CEXPR_USER) {
				if (!is_id_in_scope(SYM_USERS, id)) {
					yyerror2("user %s is not within scope",
						 id);
					constraint_expr_destroy(expr);
					return 0;
				}
				user =
				    (user_datum_t *) hashtab_search(policydbp->
								    p_users.
								    table,
								    (hashtab_key_t)
								    id);
				if (!user) {
					yyerror2("unknown user %s", id);
					constraint_expr_destroy(expr);
					return 0;
				}
				val = user->s.value;
			} else if (expr->attr & CEXPR_ROLE) {
				if (!is_id_in_scope(SYM_ROLES, id)) {
					yyerror2("role %s is not within scope",
						 id);
					constraint_expr_destroy(expr);
					return 0;
				}
				role =
				    (role_datum_t *) hashtab_search(policydbp->
								    p_roles.
								    table,
								    (hashtab_key_t)
								    id);
				if (!role) {
					yyerror2("unknown role %s", id);
					constraint_expr_destroy(expr);
					return 0;
				}
				val = role->s.value;
			} else if (expr->attr & CEXPR_TYPE) {
				if (set_types(expr->type_names, id, &add, 0)) {
					constraint_expr_destroy(expr);
					return 0;
				}
				continue;
			} else {
				yyerror("invalid constraint expression");
				constraint_expr_destroy(expr);
				return 0;
			}
			if (ebitmap_set_bit(&expr->names, val - 1, TRUE)) {
				yyerror("out of memory");
				ebitmap_destroy(&expr->names);
				constraint_expr_destroy(expr);
				return 0;
			}
			free(id);
		}
		ebitmap_destroy(&negset);
		return (uintptr_t) expr;
	default:
		break;
	}

	yyerror("invalid constraint expression");
	constraint_expr_destroy(expr);
	return 0;
}

int define_conditional(cond_expr_t * expr, avrule_t * t, avrule_t * f)
{
	cond_expr_t *e;
	int depth;
	cond_node_t cn, *cn_old;

	/* expression cannot be NULL */
	if (!expr) {
		yyerror("illegal conditional expression");
		return -1;
	}
	if (!t) {
		if (!f) {
			/* empty is fine, destroy expression and return */
			cond_expr_destroy(expr);
			return 0;
		}
		/* Invert */
		t = f;
		f = 0;
		expr = define_cond_expr(COND_NOT, expr, 0);
		if (!expr) {
			yyerror("unable to invert");
			return -1;
		}
	}

	/* verify expression */
	depth = -1;
	for (e = expr; e; e = e->next) {
		switch (e->expr_type) {
		case COND_NOT:
			if (depth < 0) {
				yyerror
				    ("illegal conditional expression; Bad NOT");
				return -1;
			}
			break;
		case COND_AND:
		case COND_OR:
		case COND_XOR:
		case COND_EQ:
		case COND_NEQ:
			if (depth < 1) {
				yyerror
				    ("illegal conditional expression; Bad binary op");
				return -1;
			}
			depth--;
			break;
		case COND_BOOL:
			if (depth == (COND_EXPR_MAXDEPTH - 1)) {
				yyerror
				    ("conditional expression is like totally too deep");
				return -1;
			}
			depth++;
			break;
		default:
			yyerror("illegal conditional expression");
			return -1;
		}
	}
	if (depth != 0) {
		yyerror("illegal conditional expression");
		return -1;
	}

	/*  use tmp conditional node to partially build new node */
	memset(&cn, 0, sizeof(cn));
	cn.expr = expr;
	cn.avtrue_list = t;
	cn.avfalse_list = f;

	/* normalize/precompute expression */
	if (cond_normalize_expr(policydbp, &cn) < 0) {
		yyerror("problem normalizing conditional expression");
		return -1;
	}

	/* get the existing conditional node, or create a new one */
	cn_old = get_current_cond_list(&cn);
	if (!cn_old) {
		return -1;
	}

	append_cond_list(&cn);

	/* note that there is no check here for duplicate rules, nor
	 * check that rule already exists in base -- that will be
	 * handled during conditional expansion, in expand.c */

	cn.avtrue_list = NULL;
	cn.avfalse_list = NULL;
	cond_node_destroy(&cn);

	return 0;
}

cond_expr_t *define_cond_expr(uint32_t expr_type, void *arg1, void *arg2)
{
	struct cond_expr *expr, *e1 = NULL, *e2;
	cond_bool_datum_t *bool_var;
	char *id;

	/* expressions are handled in the second pass */
	if (pass == 1) {
		if (expr_type == COND_BOOL) {
			while ((id = queue_remove(id_queue))) {
				free(id);
			}
		}
		return (cond_expr_t *) 1;	/* any non-NULL value */
	}

	/* create a new expression struct */
	expr = malloc(sizeof(struct cond_expr));
	if (!expr) {
		yyerror("out of memory");
		return NULL;
	}
	memset(expr, 0, sizeof(cond_expr_t));
	expr->expr_type = expr_type;

	/* create the type asked for */
	switch (expr_type) {
	case COND_NOT:
		e1 = NULL;
		e2 = (struct cond_expr *)arg1;
		while (e2) {
			e1 = e2;
			e2 = e2->next;
		}
		if (!e1 || e1->next) {
			yyerror("illegal conditional NOT expression");
			free(expr);
			return NULL;
		}
		e1->next = expr;
		return (struct cond_expr *)arg1;
	case COND_AND:
	case COND_OR:
	case COND_XOR:
	case COND_EQ:
	case COND_NEQ:
		e1 = NULL;
		e2 = (struct cond_expr *)arg1;
		while (e2) {
			e1 = e2;
			e2 = e2->next;
		}
		if (!e1 || e1->next) {
			yyerror
			    ("illegal left side of conditional binary op expression");
			free(expr);
			return NULL;
		}
		e1->next = (struct cond_expr *)arg2;

		e1 = NULL;
		e2 = (struct cond_expr *)arg2;
		while (e2) {
			e1 = e2;
			e2 = e2->next;
		}
		if (!e1 || e1->next) {
			yyerror
			    ("illegal right side of conditional binary op expression");
			free(expr);
			return NULL;
		}
		e1->next = expr;
		return (struct cond_expr *)arg1;
	case COND_BOOL:
		id = (char *)queue_remove(id_queue);
		if (!id) {
			yyerror("bad conditional; expected boolean id");
			free(id);
			free(expr);
			return NULL;
		}
		if (!is_id_in_scope(SYM_BOOLS, id)) {
			yyerror2("boolean %s is not within scope", id);
			free(id);
			free(expr);
			return NULL;
		}
		bool_var =
		    (cond_bool_datum_t *) hashtab_search(policydbp->p_bools.
							 table,
							 (hashtab_key_t) id);
		if (!bool_var) {
			yyerror2("unknown boolean %s in conditional expression",
				 id);
			free(expr);
			free(id);
			return NULL;
		}
		expr->bool = bool_var->s.value;
		free(id);
		return expr;
	default:
		yyerror("illegal conditional expression");
		free(expr);
		return NULL;
	}
}

static int set_user_roles(role_set_t * set, char *id)
{
	role_datum_t *r;
	unsigned int i;
	ebitmap_node_t *node;

	if (strcmp(id, "*") == 0) {
		free(id);
		yyerror("* is not allowed in user declarations");
		return -1;
	}

	if (strcmp(id, "~") == 0) {
		free(id);
		yyerror("~ is not allowed in user declarations");
		return -1;
	}

	if (!is_id_in_scope(SYM_ROLES, id)) {
		yyerror2("role %s is not within scope", id);
		free(id);
		return -1;
	}
	r = hashtab_search(policydbp->p_roles.table, id);
	if (!r) {
		yyerror2("unknown role %s", id);
		free(id);
		return -1;
	}

	/* set the role and every role it dominates */
	ebitmap_for_each_bit(&r->dominates, node, i) {
		if (ebitmap_node_get_bit(node, i))
			if (ebitmap_set_bit(&set->roles, i, TRUE))
				goto oom;
	}
	free(id);
	return 0;
      oom:
	yyerror("out of memory");
	return -1;
}

static int parse_categories(char *id, level_datum_t * levdatum, ebitmap_t * cats)
{
	cat_datum_t *cdatum;
	int range_start, range_end, i;

	if (id_has_dot(id)) {
		char *id_start = id;
		char *id_end = strchr(id, '.');

		*(id_end++) = '\0';

		cdatum = (cat_datum_t *) hashtab_search(policydbp->p_cats.table,
							(hashtab_key_t)
							id_start);
		if (!cdatum) {
			yyerror2("unknown category %s", id_start);
			return -1;
		}
		range_start = cdatum->s.value - 1;
		cdatum = (cat_datum_t *) hashtab_search(policydbp->p_cats.table,
							(hashtab_key_t) id_end);
		if (!cdatum) {
			yyerror2("unknown category %s", id_end);
			return -1;
		}
		range_end = cdatum->s.value - 1;

		if (range_end < range_start) {
			yyerror2("category range is invalid");
			return -1;
		}
	} else {
		cdatum = (cat_datum_t *) hashtab_search(policydbp->p_cats.table,
							(hashtab_key_t) id);
		if (!cdatum) {
			yyerror2("unknown category %s", id);
			return -1;
		}
		range_start = range_end = cdatum->s.value - 1;
	}

	for (i = range_start; i <= range_end; i++) {
		if (!ebitmap_get_bit(&levdatum->level->cat, i)) {
			uint32_t level_value = levdatum->level->sens - 1;
			policydb_index_others(NULL, policydbp, 0);
			yyerror2("category %s can not be associated "
				 "with level %s",
				 policydbp->p_cat_val_to_name[i],
				 policydbp->p_sens_val_to_name[level_value]);
			return -1;
		}
		if (ebitmap_set_bit(cats, i, TRUE)) {
			yyerror("out of memory");
			return -1;
		}
	}

	return 0;
}

static int parse_semantic_categories(char *id, level_datum_t * levdatum __attribute__ ((unused)),
				     mls_semantic_cat_t ** cats)
{
	cat_datum_t *cdatum;
	mls_semantic_cat_t *newcat;
	unsigned int range_start, range_end;

	if (id_has_dot(id)) {
		char *id_start = id;
		char *id_end = strchr(id, '.');

		*(id_end++) = '\0';

		cdatum = (cat_datum_t *) hashtab_search(policydbp->p_cats.table,
							(hashtab_key_t)
							id_start);
		if (!cdatum) {
			yyerror2("unknown category %s", id_start);
			return -1;
		}
		range_start = cdatum->s.value;

		cdatum = (cat_datum_t *) hashtab_search(policydbp->p_cats.table,
							(hashtab_key_t) id_end);
		if (!cdatum) {
			yyerror2("unknown category %s", id_end);
			return -1;
		}
		range_end = cdatum->s.value;
	} else {
		cdatum = (cat_datum_t *) hashtab_search(policydbp->p_cats.table,
							(hashtab_key_t) id);
		if (!cdatum) {
			yyerror2("unknown category %s", id);
			return -1;
		}
		range_start = range_end = cdatum->s.value;
	}

	newcat = (mls_semantic_cat_t *) malloc(sizeof(mls_semantic_cat_t));
	if (!newcat) {
		yyerror("out of memory");
		return -1;
	}

	mls_semantic_cat_init(newcat);
	newcat->next = *cats;
	newcat->low = range_start;
	newcat->high = range_end;

	*cats = newcat;

	return 0;
}

int define_user(void)
{
	char *id;
	user_datum_t *usrdatum;
	level_datum_t *levdatum;
	int l;

	if (pass == 1) {
		while ((id = queue_remove(id_queue)))
			free(id);
		if (mlspol) {
			while ((id = queue_remove(id_queue)))
				free(id);
			id = queue_remove(id_queue);
			free(id);
			for (l = 0; l < 2; l++) {
				while ((id = queue_remove(id_queue))) {
					free(id);
				}
				id = queue_remove(id_queue);
				if (!id)
					break;
				free(id);
			}
		}
		return 0;
	}

	if ((usrdatum = declare_user()) == NULL) {
		return -1;
	}

	while ((id = queue_remove(id_queue))) {
		if (set_user_roles(&usrdatum->roles, id))
			continue;
	}

	if (mlspol) {
		id = queue_remove(id_queue);
		if (!id) {
			yyerror("no default level specified for user");
			return -1;
		}

		levdatum = (level_datum_t *)
		    hashtab_search(policydbp->p_levels.table,
				   (hashtab_key_t) id);
		if (!levdatum) {
			yyerror2("unknown sensitivity %s used in user"
				 " level definition", id);
			free(id);
			return -1;
		}
		free(id);

		usrdatum->dfltlevel.sens = levdatum->level->sens;

		while ((id = queue_remove(id_queue))) {
			if (parse_semantic_categories(id, levdatum,
			                            &usrdatum->dfltlevel.cat)) {
				free(id);
				return -1;
			}
			free(id);
		}

		id = queue_remove(id_queue);

		for (l = 0; l < 2; l++) {
			levdatum = (level_datum_t *)
			    hashtab_search(policydbp->p_levels.table,
					   (hashtab_key_t) id);
			if (!levdatum) {
				yyerror2("unknown sensitivity %s used in user"
					 " range definition", id);
				free(id);
				return -1;
			}
			free(id);

			usrdatum->range.level[l].sens = levdatum->level->sens;

			while ((id = queue_remove(id_queue))) {
				if (parse_semantic_categories(id, levdatum,
				               &usrdatum->range.level[l].cat)) {
					free(id);
					return -1;
				}
				free(id);
			}

			id = queue_remove(id_queue);
			if (!id)
				break;
		}

		if (l == 0) {
			if (mls_semantic_level_cpy(&usrdatum->range.level[1],
			                           &usrdatum->range.level[0])) {
				yyerror("out of memory");
				return -1;
			}
		}
	}
	return 0;
}

static int parse_security_context(context_struct_t * c)
{
	char *id;
	role_datum_t *role;
	type_datum_t *typdatum;
	user_datum_t *usrdatum;
	level_datum_t *levdatum;
	int l;

	if (pass == 1) {
		id = queue_remove(id_queue);
		free(id);	/* user  */
		id = queue_remove(id_queue);
		free(id);	/* role  */
		id = queue_remove(id_queue);
		free(id);	/* type  */
		if (mlspol) {
			id = queue_remove(id_queue);
			free(id);
			for (l = 0; l < 2; l++) {
				while ((id = queue_remove(id_queue))) {
					free(id);
				}
				id = queue_remove(id_queue);
				if (!id)
					break;
				free(id);
			}
		}
		return 0;
	}

	/* check context c to make sure ok to dereference c later */
	if (c == NULL) {
		yyerror("null context pointer!");
		return -1;
	}

	context_init(c);

	/* extract the user */
	id = queue_remove(id_queue);
	if (!id) {
		yyerror("no effective user?");
		goto bad;
	}
	if (!is_id_in_scope(SYM_USERS, id)) {
		yyerror2("user %s is not within scope", id);
		free(id);
		goto bad;
	}
	usrdatum = (user_datum_t *) hashtab_search(policydbp->p_users.table,
						   (hashtab_key_t) id);
	if (!usrdatum) {
		yyerror2("user %s is not defined", id);
		free(id);
		goto bad;
	}
	c->user = usrdatum->s.value;

	/* no need to keep the user name */
	free(id);

	/* extract the role */
	id = (char *)queue_remove(id_queue);
	if (!id) {
		yyerror("no role name for sid context definition?");
		return -1;
	}
	if (!is_id_in_scope(SYM_ROLES, id)) {
		yyerror2("role %s is not within scope", id);
		free(id);
		return -1;
	}
	role = (role_datum_t *) hashtab_search(policydbp->p_roles.table,
					       (hashtab_key_t) id);
	if (!role) {
		yyerror2("role %s is not defined", id);
		free(id);
		return -1;
	}
	c->role = role->s.value;

	/* no need to keep the role name */
	free(id);

	/* extract the type */
	id = (char *)queue_remove(id_queue);
	if (!id) {
		yyerror("no type name for sid context definition?");
		return -1;
	}
	if (!is_id_in_scope(SYM_TYPES, id)) {
		yyerror2("type %s is not within scope", id);
		free(id);
		return -1;
	}
	typdatum = (type_datum_t *) hashtab_search(policydbp->p_types.table,
						   (hashtab_key_t) id);
	if (!typdatum || typdatum->flavor == TYPE_ATTRIB) {
		yyerror2("type %s is not defined or is an attribute", id);
		free(id);
		return -1;
	}
	c->type = typdatum->s.value;

	/* no need to keep the type name */
	free(id);

	if (mlspol) {
		/* extract the low sensitivity */
		id = (char *)queue_head(id_queue);
		if (!id) {
			yyerror("no sensitivity name for sid context"
				" definition?");
			return -1;
		}

		id = (char *)queue_remove(id_queue);
		for (l = 0; l < 2; l++) {
			levdatum = (level_datum_t *)
			    hashtab_search(policydbp->p_levels.table,
					   (hashtab_key_t) id);
			if (!levdatum) {
				yyerror2("Sensitivity %s is not defined", id);
				free(id);
				return -1;
			}
			free(id);
			c->range.level[l].sens = levdatum->level->sens;

			/* extract low category set */
			while ((id = queue_remove(id_queue))) {
				if (parse_categories(id, levdatum,
						     &c->range.level[l].cat)) {
					free(id);
					return -1;
				}
				free(id);
			}

			/* extract high sensitivity */
			id = (char *)queue_remove(id_queue);
			if (!id)
				break;
		}

		if (l == 0) {
			c->range.level[1].sens = c->range.level[0].sens;
			if (ebitmap_cpy(&c->range.level[1].cat,
					&c->range.level[0].cat)) {

				yyerror("out of memory");
				goto bad;
			}
		}
	}

	if (!policydb_context_isvalid(policydbp, c)) {
		yyerror("invalid security context");
		goto bad;
	}
	return 0;

      bad:
	context_destroy(c);

	return -1;
}

int define_initial_sid_context(void)
{
	char *id;
	ocontext_t *c, *head;

	if (pass == 1) {
		id = (char *)queue_remove(id_queue);
		free(id);
		parse_security_context(NULL);
		return 0;
	}

	id = (char *)queue_remove(id_queue);
	if (!id) {
		yyerror("no sid name for SID context definition?");
		return -1;
	}
	head = policydbp->ocontexts[OCON_ISID];
	for (c = head; c; c = c->next) {
		if (!strcmp(id, c->u.name))
			break;
	}

	if (!c) {
		yyerror2("SID %s is not defined", id);
		free(id);
		return -1;
	}
	if (c->context[0].user) {
		yyerror2("The context for SID %s is multiply defined", id);
		free(id);
		return -1;
	}
	/* no need to keep the sid name */
	free(id);

	if (parse_security_context(&c->context[0]))
		return -1;

	return 0;
}

int define_fs_context(unsigned int major, unsigned int minor)
{
	ocontext_t *newc, *c, *head;

	if (policydbp->target_platform != SEPOL_TARGET_SELINUX) {
		yyerror("fscon not supported for target");
		return -1;
	}

	if (pass == 1) {
		parse_security_context(NULL);
		parse_security_context(NULL);
		return 0;
	}

	newc = (ocontext_t *) malloc(sizeof(ocontext_t));
	if (!newc) {
		yyerror("out of memory");
		return -1;
	}
	memset(newc, 0, sizeof(ocontext_t));

	newc->u.name = (char *)malloc(6);
	if (!newc->u.name) {
		yyerror("out of memory");
		free(newc);
		return -1;
	}
	sprintf(newc->u.name, "%02x:%02x", major, minor);

	if (parse_security_context(&newc->context[0])) {
		free(newc->u.name);
		free(newc);
		return -1;
	}
	if (parse_security_context(&newc->context[1])) {
		context_destroy(&newc->context[0]);
		free(newc->u.name);
		free(newc);
		return -1;
	}
	head = policydbp->ocontexts[OCON_FS];

	for (c = head; c; c = c->next) {
		if (!strcmp(newc->u.name, c->u.name)) {
			yyerror2("duplicate entry for file system %s",
				 newc->u.name);
			context_destroy(&newc->context[0]);
			context_destroy(&newc->context[1]);
			free(newc->u.name);
			free(newc);
			return -1;
		}
	}

	newc->next = head;
	policydbp->ocontexts[OCON_FS] = newc;

	return 0;
}

int define_pirq_context(unsigned int pirq)
{
	ocontext_t *newc, *c, *l, *head;
	char *id;

	if (policydbp->target_platform != SEPOL_TARGET_XEN) {
		yyerror("pirqcon not supported for target");
		return -1;
	}

	if (pass == 1) {
		id = (char *) queue_remove(id_queue);
		free(id);
		parse_security_context(NULL);
		return 0;
	}

	newc = malloc(sizeof(ocontext_t));
	if (!newc) {
		yyerror("out of memory");
		return -1;
	}
	memset(newc, 0, sizeof(ocontext_t));

	newc->u.pirq = pirq;

	if (parse_security_context(&newc->context[0])) {
		free(newc);
		return -1;
	}

	head = policydbp->ocontexts[OCON_XEN_PIRQ];
	for (l = NULL, c = head; c; l = c, c = c->next) {
		unsigned int pirq2;

		pirq2 = c->u.pirq;
		if (pirq == pirq2) {
			yyerror2("duplicate pirqcon entry for %d ", pirq);
			goto bad;
		}
	}

	if (l)
		l->next = newc;
	else
		policydbp->ocontexts[OCON_XEN_PIRQ] = newc;

	return 0;

bad:
	free(newc);
	return -1;
}

int define_iomem_context(uint64_t low, uint64_t high)
{
	ocontext_t *newc, *c, *l, *head;
	char *id;

	if (policydbp->target_platform != SEPOL_TARGET_XEN) {
		yyerror("iomemcon not supported for target");
		return -1;
	}

	if (pass == 1) {
		id = (char *)queue_remove(id_queue);
		free(id);
		parse_security_context(NULL);
		return 0;
	}

	newc = malloc(sizeof(ocontext_t));
	if (!newc) {
		yyerror("out of memory");
		return -1;
	}
	memset(newc, 0, sizeof(ocontext_t));

	newc->u.iomem.low_iomem  = low;
	newc->u.iomem.high_iomem = high;

	if (low > high) {
		yyerror2("low memory 0x%"PRIx64" exceeds high memory 0x%"PRIx64"", low, high);
		free(newc);
		return -1;
	}

	if (parse_security_context(&newc->context[0])) {
		free(newc);
		return -1;
	}

	head = policydbp->ocontexts[OCON_XEN_IOMEM];
	for (l = NULL, c = head; c; l = c, c = c->next) {
		uint64_t low2, high2;

		low2 = c->u.iomem.low_iomem;
		high2 = c->u.iomem.high_iomem;
		if (low <= high2 && low2 <= high) {
			yyerror2("iomemcon entry for 0x%"PRIx64"-0x%"PRIx64" overlaps with "
				"earlier entry 0x%"PRIx64"-0x%"PRIx64"", low, high,
				low2, high2);
			goto bad;
		}
	}

	if (l)
		l->next = newc;
	else
		policydbp->ocontexts[OCON_XEN_IOMEM] = newc;

	return 0;

bad:
	free(newc);
	return -1;
}

int define_ioport_context(unsigned long low, unsigned long high)
{
	ocontext_t *newc, *c, *l, *head;
	char *id;

	if (policydbp->target_platform != SEPOL_TARGET_XEN) {
		yyerror("ioportcon not supported for target");
		return -1;
	}

	if (pass == 1) {
		id = (char *)queue_remove(id_queue);
		free(id);
		parse_security_context(NULL);
		return 0;
	}

	newc = malloc(sizeof(ocontext_t));
	if (!newc) {
		yyerror("out of memory");
		return -1;
	}
	memset(newc, 0, sizeof(ocontext_t));

	newc->u.ioport.low_ioport  = low;
	newc->u.ioport.high_ioport = high;

	if (low > high) {
		yyerror2("low ioport 0x%lx exceeds high ioport 0x%lx", low, high);
		free(newc);
		return -1;
	}

	if (parse_security_context(&newc->context[0])) {
		free(newc);
		return -1;
	}

	head = policydbp->ocontexts[OCON_XEN_IOPORT];
	for (l = NULL, c = head; c; l = c, c = c->next) {
		uint32_t low2, high2;

		low2 = c->u.ioport.low_ioport;
		high2 = c->u.ioport.high_ioport;
		if (low <= high2 && low2 <= high) {
			yyerror2("ioportcon entry for 0x%lx-0x%lx overlaps with"
				"earlier entry 0x%x-0x%x", low, high,
				low2, high2);
			goto bad;
		}
	}

	if (l)
		l->next = newc;
	else
		policydbp->ocontexts[OCON_XEN_IOPORT] = newc;

	return 0;

bad:
	free(newc);
	return -1;
}

int define_pcidevice_context(unsigned long device)
{
	ocontext_t *newc, *c, *l, *head;
	char *id;

	if (policydbp->target_platform != SEPOL_TARGET_XEN) {
		yyerror("pcidevicecon not supported for target");
		return -1;
	}

	if (pass == 1) {
		id = (char *) queue_remove(id_queue);
		free(id);
		parse_security_context(NULL);
		return 0;
	}

	newc = malloc(sizeof(ocontext_t));
	if (!newc) {
		yyerror("out of memory");
		return -1;
	}
	memset(newc, 0, sizeof(ocontext_t));

	newc->u.device = device;

	if (parse_security_context(&newc->context[0])) {
		free(newc);
		return -1;
	}

	head = policydbp->ocontexts[OCON_XEN_PCIDEVICE];
	for (l = NULL, c = head; c; l = c, c = c->next) {
		unsigned int device2;

		device2 = c->u.device;
		if (device == device2) {
			yyerror2("duplicate pcidevicecon entry for 0x%lx",
				 device);
			goto bad;
		}
	}

	if (l)
		l->next = newc;
	else
		policydbp->ocontexts[OCON_XEN_PCIDEVICE] = newc;

	return 0;

bad:
	free(newc);
	return -1;
}

int define_devicetree_context()
{
	ocontext_t *newc, *c, *l, *head;

	if (policydbp->target_platform != SEPOL_TARGET_XEN) {
		yyerror("devicetreecon not supported for target");
		return -1;
	}

	if (pass == 1) {
		free(queue_remove(id_queue));
		parse_security_context(NULL);
		return 0;
	}

	newc = malloc(sizeof(ocontext_t));
	if (!newc) {
		yyerror("out of memory");
		return -1;
	}
	memset(newc, 0, sizeof(ocontext_t));

	newc->u.name = (char *)queue_remove(id_queue);
	if (!newc->u.name) {
		free(newc);
		return -1;
	}

	if (parse_security_context(&newc->context[0])) {
		free(newc->u.name);
		free(newc);
		return -1;
	}

	head = policydbp->ocontexts[OCON_XEN_DEVICETREE];
	for (l = NULL, c = head; c; l = c, c = c->next) {
		if (strcmp(newc->u.name, c->u.name) == 0) {
			yyerror2("duplicate devicetree entry for '%s'", newc->u.name);
			goto bad;
		}
	}

	if (l)
		l->next = newc;
	else
		policydbp->ocontexts[OCON_XEN_DEVICETREE] = newc;

	return 0;

bad:
	free(newc->u.name);
	free(newc);
	return -1;
}

int define_port_context(unsigned int low, unsigned int high)
{
	ocontext_t *newc, *c, *l, *head;
	unsigned int protocol;
	char *id;

	if (policydbp->target_platform != SEPOL_TARGET_SELINUX) {
		yyerror("portcon not supported for target");
		return -1;
	}

	if (pass == 1) {
		id = (char *)queue_remove(id_queue);
		free(id);
		parse_security_context(NULL);
		return 0;
	}

	newc = malloc(sizeof(ocontext_t));
	if (!newc) {
		yyerror("out of memory");
		return -1;
	}
	memset(newc, 0, sizeof(ocontext_t));

	id = (char *)queue_remove(id_queue);
	if (!id) {
		free(newc);
		return -1;
	}
	if ((strcmp(id, "tcp") == 0) || (strcmp(id, "TCP") == 0)) {
		protocol = IPPROTO_TCP;
	} else if ((strcmp(id, "udp") == 0) || (strcmp(id, "UDP") == 0)) {
		protocol = IPPROTO_UDP;
	} else if ((strcmp(id, "dccp") == 0) || (strcmp(id, "DCCP") == 0)) {
		protocol = IPPROTO_DCCP;
	} else {
		yyerror2("unrecognized protocol %s", id);
		goto bad;
	}

	newc->u.port.protocol = protocol;
	newc->u.port.low_port = low;
	newc->u.port.high_port = high;

	if (low > high) {
		yyerror2("low port %d exceeds high port %d", low, high);
		goto bad;
	}

	if (parse_security_context(&newc->context[0])) {
		goto bad;
	}

	/* Preserve the matching order specified in the configuration. */
	head = policydbp->ocontexts[OCON_PORT];
	for (l = NULL, c = head; c; l = c, c = c->next) {
		unsigned int prot2, low2, high2;

		prot2 = c->u.port.protocol;
		low2 = c->u.port.low_port;
		high2 = c->u.port.high_port;
		if (protocol != prot2)
			continue;
		if (low == low2 && high == high2) {
			yyerror2("duplicate portcon entry for %s %d-%d ", id,
				 low, high);
			goto bad;
		}
		if (low2 <= low && high2 >= high) {
			yyerror2("portcon entry for %s %d-%d hidden by earlier "
				 "entry for %d-%d", id, low, high, low2, high2);
			goto bad;
		}
	}

	if (l)
		l->next = newc;
	else
		policydbp->ocontexts[OCON_PORT] = newc;

	free(id);
	return 0;

      bad:
	free(id);
	free(newc);
	return -1;
}

int define_netif_context(void)
{
	ocontext_t *newc, *c, *head;

	if (policydbp->target_platform != SEPOL_TARGET_SELINUX) {
		yyerror("netifcon not supported for target");
		return -1;
	}

	if (pass == 1) {
		free(queue_remove(id_queue));
		parse_security_context(NULL);
		parse_security_context(NULL);
		return 0;
	}

	newc = (ocontext_t *) malloc(sizeof(ocontext_t));
	if (!newc) {
		yyerror("out of memory");
		return -1;
	}
	memset(newc, 0, sizeof(ocontext_t));

	newc->u.name = (char *)queue_remove(id_queue);
	if (!newc->u.name) {
		free(newc);
		return -1;
	}
	if (parse_security_context(&newc->context[0])) {
		free(newc->u.name);
		free(newc);
		return -1;
	}
	if (parse_security_context(&newc->context[1])) {
		context_destroy(&newc->context[0]);
		free(newc->u.name);
		free(newc);
		return -1;
	}
	head = policydbp->ocontexts[OCON_NETIF];

	for (c = head; c; c = c->next) {
		if (!strcmp(newc->u.name, c->u.name)) {
			yyerror2("duplicate entry for network interface %s",
				 newc->u.name);
			context_destroy(&newc->context[0]);
			context_destroy(&newc->context[1]);
			free(newc->u.name);
			free(newc);
			return -1;
		}
	}

	newc->next = head;
	policydbp->ocontexts[OCON_NETIF] = newc;
	return 0;
}

int define_ipv4_node_context()
{	
	char *id;
	int rc = 0;
	struct in_addr addr, mask;
	ocontext_t *newc, *c, *l, *head;

	if (policydbp->target_platform != SEPOL_TARGET_SELINUX) {
		yyerror("nodecon not supported for target");
		return -1;
	}

	if (pass == 1) {
		free(queue_remove(id_queue));
		free(queue_remove(id_queue));
		parse_security_context(NULL);
		goto out;
	}

	id = queue_remove(id_queue);
	if (!id) {
		yyerror("failed to read ipv4 address");
		rc = -1;
		goto out;
	}

	rc = inet_pton(AF_INET, id, &addr);
	free(id);
	if (rc < 1) {
		yyerror("failed to parse ipv4 address");
		if (rc == 0)
			rc = -1;
		goto out;
	}

	id = queue_remove(id_queue);
	if (!id) {
		yyerror("failed to read ipv4 address");
		rc = -1;
		goto out;
	}

	rc = inet_pton(AF_INET, id, &mask);
	free(id);
	if (rc < 1) {
		yyerror("failed to parse ipv4 mask");
		if (rc == 0)
			rc = -1;
		goto out;
	}

	newc = malloc(sizeof(ocontext_t));
	if (!newc) {
		yyerror("out of memory");
		rc = -1;
		goto out;
	}

	memset(newc, 0, sizeof(ocontext_t));
	newc->u.node.addr = addr.s_addr;
	newc->u.node.mask = mask.s_addr;

	if (parse_security_context(&newc->context[0])) {
		free(newc);
		return -1;
	}

	/* Create order of most specific to least retaining
	   the order specified in the configuration. */
	head = policydbp->ocontexts[OCON_NODE];
	for (l = NULL, c = head; c; l = c, c = c->next) {
		if (newc->u.node.mask > c->u.node.mask)
			break;
	}

	newc->next = c;

	if (l)
		l->next = newc;
	else
		policydbp->ocontexts[OCON_NODE] = newc;
	rc = 0;
out:
	return rc;
}

int define_ipv6_node_context(void)
{
	char *id;
	int rc = 0;
	struct in6_addr addr, mask;
	ocontext_t *newc, *c, *l, *head;

	if (policydbp->target_platform != SEPOL_TARGET_SELINUX) {
		yyerror("nodecon not supported for target");
		return -1;
	}

	if (pass == 1) {
		free(queue_remove(id_queue));
		free(queue_remove(id_queue));
		parse_security_context(NULL);
		goto out;
	}

	id = queue_remove(id_queue);
	if (!id) {
		yyerror("failed to read ipv6 address");
		rc = -1;
		goto out;
	}

	rc = inet_pton(AF_INET6, id, &addr);
	free(id);
	if (rc < 1) {
		yyerror("failed to parse ipv6 address");
		if (rc == 0)
			rc = -1;
		goto out;
	}

	id = queue_remove(id_queue);
	if (!id) {
		yyerror("failed to read ipv6 address");
		rc = -1;
		goto out;
	}

	rc = inet_pton(AF_INET6, id, &mask);
	free(id);
	if (rc < 1) {
		yyerror("failed to parse ipv6 mask");
		if (rc == 0)
			rc = -1;
		goto out;
	}

	newc = malloc(sizeof(ocontext_t));
	if (!newc) {
		yyerror("out of memory");
		rc = -1;
		goto out;
	}

	memset(newc, 0, sizeof(ocontext_t));

#ifdef __APPLE__
	memcpy(&newc->u.node6.addr[0], &addr.s6_addr[0], 16);
	memcpy(&newc->u.node6.mask[0], &mask.s6_addr[0], 16);
#else
	memcpy(&newc->u.node6.addr[0], &addr.s6_addr32[0], 16);
	memcpy(&newc->u.node6.mask[0], &mask.s6_addr32[0], 16);
#endif

	if (parse_security_context(&newc->context[0])) {
		free(newc);
		rc = -1;
		goto out;
	}

	/* Create order of most specific to least retaining
	   the order specified in the configuration. */
	head = policydbp->ocontexts[OCON_NODE6];
	for (l = NULL, c = head; c; l = c, c = c->next) {
		if (memcmp(&newc->u.node6.mask, &c->u.node6.mask, 16) > 0)
			break;
	}

	newc->next = c;

	if (l)
		l->next = newc;
	else
		policydbp->ocontexts[OCON_NODE6] = newc;

	rc = 0;
      out:
	return rc;
}

int define_fs_use(int behavior)
{
	ocontext_t *newc, *c, *head;

	if (policydbp->target_platform != SEPOL_TARGET_SELINUX) {
		yyerror("fsuse not supported for target");
		return -1;
	}

	if (pass == 1) {
		free(queue_remove(id_queue));
		parse_security_context(NULL);
		return 0;
	}

	newc = (ocontext_t *) malloc(sizeof(ocontext_t));
	if (!newc) {
		yyerror("out of memory");
		return -1;
	}
	memset(newc, 0, sizeof(ocontext_t));

	newc->u.name = (char *)queue_remove(id_queue);
	if (!newc->u.name) {
		free(newc);
		return -1;
	}
	newc->v.behavior = behavior;
	if (parse_security_context(&newc->context[0])) {
		free(newc->u.name);
		free(newc);
		return -1;
	}

	head = policydbp->ocontexts[OCON_FSUSE];

	for (c = head; c; c = c->next) {
		if (!strcmp(newc->u.name, c->u.name)) {
			yyerror2("duplicate fs_use entry for filesystem type %s",
				 newc->u.name);
			context_destroy(&newc->context[0]);
			free(newc->u.name);
			free(newc);
			return -1;
		}
	}

	newc->next = head;
	policydbp->ocontexts[OCON_FSUSE] = newc;
	return 0;
}

int define_genfs_context_helper(char *fstype, int has_type)
{
	struct genfs *genfs_p, *genfs, *newgenfs;
	ocontext_t *newc, *c, *head, *p;
	char *type = NULL;
	int len, len2;

	if (policydbp->target_platform != SEPOL_TARGET_SELINUX) {
		yyerror("genfs not supported for target");
		return -1;
	}

	if (pass == 1) {
		free(fstype);
		free(queue_remove(id_queue));
		if (has_type)
			free(queue_remove(id_queue));
		parse_security_context(NULL);
		return 0;
	}

	for (genfs_p = NULL, genfs = policydbp->genfs;
	     genfs; genfs_p = genfs, genfs = genfs->next) {
		if (strcmp(fstype, genfs->fstype) <= 0)
			break;
	}

	if (!genfs || strcmp(fstype, genfs->fstype)) {
		newgenfs = malloc(sizeof(struct genfs));
		if (!newgenfs) {
			yyerror("out of memory");
			return -1;
		}
		memset(newgenfs, 0, sizeof(struct genfs));
		newgenfs->fstype = fstype;
		newgenfs->next = genfs;
		if (genfs_p)
			genfs_p->next = newgenfs;
		else
			policydbp->genfs = newgenfs;
		genfs = newgenfs;
	} else {
		free(fstype);
		fstype = NULL;
	}

	newc = (ocontext_t *) malloc(sizeof(ocontext_t));
	if (!newc) {
		yyerror("out of memory");
		return -1;
	}
	memset(newc, 0, sizeof(ocontext_t));

	newc->u.name = (char *)queue_remove(id_queue);
	if (!newc->u.name)
		goto fail;
	if (has_type) {
		type = (char *)queue_remove(id_queue);
		if (!type)
			goto fail;
		if (type[1] != 0) {
			yyerror2("invalid type %s", type);
			goto fail;
		}
		switch (type[0]) {
		case 'b':
			newc->v.sclass = SECCLASS_BLK_FILE;
			break;
		case 'c':
			newc->v.sclass = SECCLASS_CHR_FILE;
			break;
		case 'd':
			newc->v.sclass = SECCLASS_DIR;
			break;
		case 'p':
			newc->v.sclass = SECCLASS_FIFO_FILE;
			break;
		case 'l':
			newc->v.sclass = SECCLASS_LNK_FILE;
			break;
		case 's':
			newc->v.sclass = SECCLASS_SOCK_FILE;
			break;
		case '-':
			newc->v.sclass = SECCLASS_FILE;
			break;
		default:
			yyerror2("invalid type %s", type);
			goto fail;
		}
	}
	if (parse_security_context(&newc->context[0]))
		goto fail;

	head = genfs->head;

	for (p = NULL, c = head; c; p = c, c = c->next) {
		if (!strcmp(newc->u.name, c->u.name) &&
		    (!newc->v.sclass || !c->v.sclass
		     || newc->v.sclass == c->v.sclass)) {
			yyerror2("duplicate entry for genfs entry (%s, %s)",
				 genfs->fstype, newc->u.name);
			goto fail;
		}
		len = strlen(newc->u.name);
		len2 = strlen(c->u.name);
		if (len > len2)
			break;
	}

	newc->next = c;
	if (p)
		p->next = newc;
	else
		genfs->head = newc;
	free(type);
	return 0;
      fail:
	if (type)
		free(type);
	context_destroy(&newc->context[0]);
	if (fstype)
		free(fstype);
	if (newc->u.name)
		free(newc->u.name);
	free(newc);
	return -1;
}

int define_genfs_context(int has_type)
{
	return define_genfs_context_helper(queue_remove(id_queue), has_type);
}

int define_range_trans(int class_specified)
{
	char *id;
	level_datum_t *levdatum = 0;
	class_datum_t *cladatum;
	range_trans_rule_t *rule;
	int l, add = 1;

	if (!mlspol) {
		yyerror("range_transition rule in non-MLS configuration");
		return -1;
	}

	if (pass == 1) {
		while ((id = queue_remove(id_queue)))
			free(id);
		while ((id = queue_remove(id_queue)))
			free(id);
		if (class_specified)
			while ((id = queue_remove(id_queue)))
				free(id);
		id = queue_remove(id_queue);
		free(id);
		for (l = 0; l < 2; l++) {
			while ((id = queue_remove(id_queue))) {
				free(id);
			}
			id = queue_remove(id_queue);
			if (!id)
				break;
			free(id);
		}
		return 0;
	}

	rule = malloc(sizeof(struct range_trans_rule));
	if (!rule) {
		yyerror("out of memory");
		return -1;
	}
	range_trans_rule_init(rule);

	while ((id = queue_remove(id_queue))) {
		if (set_types(&rule->stypes, id, &add, 0))
			goto out;
	}
	add = 1;
	while ((id = queue_remove(id_queue))) {
		if (set_types(&rule->ttypes, id, &add, 0))
			goto out;
	}

	if (class_specified) {
		if (read_classes(&rule->tclasses))
			goto out;
	} else {
		cladatum = hashtab_search(policydbp->p_classes.table,
		                          "process");
		if (!cladatum) {
			yyerror2("could not find process class for "
			         "legacy range_transition statement");
			goto out;
		}

		if (ebitmap_set_bit(&rule->tclasses, cladatum->s.value - 1, TRUE)) {
			yyerror("out of memory");
			goto out;
		}
	}

	id = (char *)queue_remove(id_queue);
	if (!id) {
		yyerror("no range in range_transition definition?");
		goto out;
	}
	for (l = 0; l < 2; l++) {
		levdatum = hashtab_search(policydbp->p_levels.table, id);
		if (!levdatum) {
			yyerror2("unknown level %s used in range_transition "
			         "definition", id);
			free(id);
			goto out;
		}
		free(id);

		rule->trange.level[l].sens = levdatum->level->sens;

		while ((id = queue_remove(id_queue))) {
			if (parse_semantic_categories(id, levdatum,
			                          &rule->trange.level[l].cat)) {
				free(id);
				goto out;
			}
			free(id);
		}

		id = (char *)queue_remove(id_queue);
		if (!id)
			break;
	}
	if (l == 0) {
		if (mls_semantic_level_cpy(&rule->trange.level[1],
		                           &rule->trange.level[0])) {
			yyerror("out of memory");
			goto out;
		}
	}

	append_range_trans(rule);
	return 0;

out:
	range_trans_rule_destroy(rule);
	free(rule);
	return -1;
}

/* FLASK */
