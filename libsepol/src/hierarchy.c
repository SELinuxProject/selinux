/* Authors: Joshua Brindle <jbrindle@tresys.com>
 * 	    Jason Tang <jtang@tresys.com>
 *
 * A set of utility functions that aid policy decision when dealing
 * with hierarchal namespaces.
 *
 * Copyright (C) 2005 Tresys Technology, LLC
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/conditional.h>
#include <sepol/policydb/hierarchy.h>
#include <sepol/policydb/expand.h>
#include <sepol/policydb/util.h>

#include "debug.h"

typedef struct hierarchy_args {
	policydb_t *p;
	avtab_t *expa;		/* expanded avtab */
	/* This tells check_avtab_hierarchy to check this list in addition to the unconditional avtab */
	cond_av_list_t *opt_cond_list;
	sepol_handle_t *handle;
	int numerr;
} hierarchy_args_t;

/* This merely returns the string part before the last '.'
 * it does no verification of the existance of the parent
 * in the policy, you must do this yourself.
 *
 * Caller must free parent after use.
 */
static int find_parent(char *type, char **parent)
{
	char *tmp;
	int len;

	assert(type);

	tmp = strrchr(type, '.');
	/* no '.' means it has no parent */
	if (!tmp) {
		*parent = NULL;
		return 0;
	}

	/* allocate buffer for part of string before the '.' */
	len = tmp - type;
	*parent = (char *)malloc(sizeof(char) * (len + 1));

	if (!(*parent))
		return -1;
	memcpy(*parent, type, len);
	(*parent)[len] = '\0';

	return 0;
}

/* This function verifies that the type passed in either has a parent or is in the 
 * root of the namespace, 0 on success, 1 on orphan and -1 on error
 */
static int check_type_hierarchy_callback(hashtab_key_t k, hashtab_datum_t d,
					 void *args)
{
	char *parent;
	hierarchy_args_t *a;
	type_datum_t *t, *t2;
	char *key;

	a = (hierarchy_args_t *) args;
	t = (type_datum_t *) d;
	key = (char *)k;

	if (t->flavor == TYPE_ATTRIB) {
		/* It's an attribute, we don't care */
		return 0;
	}

	if (find_parent(key, &parent))
		return -1;

	if (!parent) {
		/* This type is in the root namespace */
		return 0;
	}

	t2 = hashtab_search(a->p->p_types.table, parent);
	if (!t2) {
		/* If the parent does not exist this type is an orphan, not legal */
		ERR(a->handle, "type %s does not exist, %s is an orphan",
		    parent, a->p->p_type_val_to_name[t->s.value - 1]);
		a->numerr++;
	} else if (t2->flavor == TYPE_ATTRIB) {
		/* The parent is an attribute but the child isn't, not legal */
		ERR(a->handle, "type %s is a child of an attribute",
		    a->p->p_type_val_to_name[t->s.value - 1]);
		a->numerr++;
	}
	free(parent);
	return 0;
}

/* This function only verifies that the avtab node passed in does not violate any
 * hiearchy constraint via any relationship with other types in the avtab.
 * it should be called using avtab_map, returns 0 on success, 1 on violation and
 * -1 on error. opt_cond_list is an optional argument that tells this to check
 * a conditional list for the relationship as well as the unconditional avtab
 */
static int check_avtab_hierarchy_callback(avtab_key_t * k, avtab_datum_t * d,
					  void *args)
{
	char *parent;
	avtab_key_t key;
	avtab_datum_t *avdatump;
	hierarchy_args_t *a;
	uint32_t av = 0;
	type_datum_t *t = NULL, *t2 = NULL;

	if (!(k->specified & AVTAB_ALLOWED)) {
		/* This is not an allow rule, no checking done */
		return 0;
	}

	a = (hierarchy_args_t *) args;
	if (find_parent(a->p->p_type_val_to_name[k->source_type - 1], &parent))
		return -1;

	/* search for parent first */
	if (parent) {
		t = hashtab_search(a->p->p_types.table, parent);
		if (!t) {
			/* This error was already covered by type_check_hierarchy */
			free(parent);
			return 0;
		}
		free(parent);

		key.source_type = t->s.value;
		key.target_type = k->target_type;
		key.target_class = k->target_class;
		key.specified = AVTAB_ALLOWED;

		avdatump = avtab_search(a->expa, &key);
		if (avdatump) {
			/* search for access allowed between type 1's parent and type 2 */
			if ((avdatump->data & d->data) == d->data) {
				return 0;
			}
			av = avdatump->data;
		}
		if (a->opt_cond_list) {
			/* if a conditional list is present search it before continuing */
			avdatump = cond_av_list_search(&key, a->opt_cond_list);
			if (avdatump) {
				if (((av | avdatump->data) & d->data) ==
				    d->data) {
					return 0;
				}
			}
		}
	}

	/* next we try type 1 and type 2's parent */
	if (find_parent(a->p->p_type_val_to_name[k->target_type - 1], &parent))
		return -1;

	if (parent) {
		t2 = hashtab_search(a->p->p_types.table, parent);
		if (!t2) {
			/* This error was already covered by type_check_hierarchy */
			free(parent);
			return 0;
		}
		free(parent);

		key.source_type = k->source_type;
		key.target_type = t2->s.value;
		key.target_class = k->target_class;
		key.specified = AVTAB_ALLOWED;

		avdatump = avtab_search(a->expa, &key);
		if (avdatump) {
			if ((avdatump->data & d->data) == d->data) {
				return 0;
			}
			av = avdatump->data;
		}
		if (a->opt_cond_list) {
			/* if a conditional list is present search it before continuing */
			avdatump = cond_av_list_search(&key, a->opt_cond_list);
			if (avdatump) {
				if (((av | avdatump->data) & d->data) ==
				    d->data) {
					return 0;
				}
			}
		}
	}

	if (t && t2) {
		key.source_type = t->s.value;
		key.target_type = t2->s.value;
		key.target_class = k->target_class;
		key.specified = AVTAB_ALLOWED;

		avdatump = avtab_search(a->expa, &key);
		if (avdatump) {
			if ((avdatump->data & d->data) == d->data) {
				return 0;
			}
			av = avdatump->data;
		}
		if (a->opt_cond_list) {
			/* if a conditional list is present search it before continuing */
			avdatump = cond_av_list_search(&key, a->opt_cond_list);
			if (avdatump) {
				if (((av | avdatump->data) & d->data) ==
				    d->data) {
					return 0;
				}
			}
		}
	}

	if (!t && !t2) {
		/* Neither one of these types have parents and 
		 * therefore the hierarchical constraint does not apply */
		return 0;
	}

	/* At this point there is a violation of the hierarchal constraint, send error condition back */
	ERR(a->handle,
	    "hierarchy violation between types %s and %s : %s { %s }",
	    a->p->p_type_val_to_name[k->source_type - 1],
	    a->p->p_type_val_to_name[k->target_type - 1],
	    a->p->p_class_val_to_name[k->target_class - 1],
	    sepol_av_to_string(a->p, k->target_class, d->data & ~av));
	a->numerr++;
	return 0;
}

static int check_cond_avtab_hierarchy(cond_list_t * cond_list,
				      hierarchy_args_t * args)
{
	int rc;
	cond_list_t *cur_node;
	cond_av_list_t *cur_av, *expl = NULL;
	avtab_t expa;
	hierarchy_args_t *a = (hierarchy_args_t *) args;

	for (cur_node = cond_list; cur_node != NULL; cur_node = cur_node->next) {
		if (avtab_init(&expa))
			goto oom;
		if (expand_cond_av_list
		    (args->p, cur_node->true_list, &expl, &expa)) {
			avtab_destroy(&expa);
			goto oom;
		}
		args->opt_cond_list = expl;
		for (cur_av = expl; cur_av != NULL; cur_av = cur_av->next) {
			rc = check_avtab_hierarchy_callback(&cur_av->node->key,
							    &cur_av->node->
							    datum, args);
			if (rc)
				a->numerr++;
		}
		cond_av_list_destroy(expl);
		avtab_destroy(&expa);
		if (avtab_init(&expa))
			goto oom;
		if (expand_cond_av_list
		    (args->p, cur_node->false_list, &expl, &expa)) {
			avtab_destroy(&expa);
			goto oom;
		}
		args->opt_cond_list = expl;
		for (cur_av = expl; cur_av != NULL; cur_av = cur_av->next) {
			rc = check_avtab_hierarchy_callback(&cur_av->node->key,
							    &cur_av->node->
							    datum, args);
			if (rc)
				a->numerr++;
		}
		cond_av_list_destroy(expl);
		avtab_destroy(&expa);
	}

	return 0;

      oom:
	ERR(args->handle, "out of memory on conditional av list expansion");
	return 1;
}

/* The role hierarchy is defined as: a child role cannot have more types than it's parent.
 * This function should be called with hashtab_map, it will return 0 on success, 1 on 
 * constraint violation and -1 on error
 */
static int check_role_hierarchy_callback(hashtab_key_t k
					 __attribute__ ((unused)),
					 hashtab_datum_t d, void *args)
{
	char *parent;
	hierarchy_args_t *a;
	role_datum_t *r, *rp;

	a = (hierarchy_args_t *) args;
	r = (role_datum_t *) d;

	if (find_parent(a->p->p_role_val_to_name[r->s.value - 1], &parent))
		return -1;

	if (!parent) {
		/* This role has no parent */
		return 0;
	}

	rp = hashtab_search(a->p->p_roles.table, parent);
	if (!rp) {
		/* Orphan role */
		ERR(a->handle, "role %s doesn't exist, %s is an orphan",
		    parent, a->p->p_role_val_to_name[r->s.value - 1]);
		free(parent);
		a->numerr++;
		return 0;
	}

	if (!ebitmap_contains(&rp->types.types, &r->types.types)) {
		/* This is a violation of the hiearchal constraint, return error condition */
		ERR(a->handle, "Role hierarchy violation, %s exceeds %s",
		    a->p->p_role_val_to_name[r->s.value - 1], parent);
		a->numerr++;
	}

	free(parent);

	return 0;
}

/* The user hierarchy is defined as: a child user cannot have a role that
 * its parent doesn't have.  This function should be called with hashtab_map,
 * it will return 0 on success, 1 on constraint violation and -1 on error.
 */
static int check_user_hierarchy_callback(hashtab_key_t k
					 __attribute__ ((unused)),
					 hashtab_datum_t d, void *args)
{
	char *parent;
	hierarchy_args_t *a;
	user_datum_t *u, *up;

	a = (hierarchy_args_t *) args;
	u = (user_datum_t *) d;

	if (find_parent(a->p->p_user_val_to_name[u->s.value - 1], &parent))
		return -1;

	if (!parent) {
		/* This user has no parent */
		return 0;
	}

	up = hashtab_search(a->p->p_users.table, parent);
	if (!up) {
		/* Orphan user */
		ERR(a->handle, "user %s doesn't exist, %s is an orphan",
		    parent, a->p->p_user_val_to_name[u->s.value - 1]);
		free(parent);
		a->numerr++;
		return 0;
	}

	if (!ebitmap_contains(&up->roles.roles, &u->roles.roles)) {
		/* hierarchical constraint violation, return error */
		ERR(a->handle, "User hierarchy violation, %s exceeds %s",
		    a->p->p_user_val_to_name[u->s.value - 1], parent);
		a->numerr++;
	}

	free(parent);

	return 0;
}

int hierarchy_check_constraints(sepol_handle_t * handle, policydb_t * p)
{
	hierarchy_args_t args;
	avtab_t expa;

	if (avtab_init(&expa))
		goto oom;
	if (expand_avtab(p, &p->te_avtab, &expa)) {
		avtab_destroy(&expa);
		goto oom;
	}

	args.p = p;
	args.expa = &expa;
	args.opt_cond_list = NULL;
	args.handle = handle;
	args.numerr = 0;

	if (hashtab_map(p->p_types.table, check_type_hierarchy_callback, &args))
		goto bad;

	if (avtab_map(&expa, check_avtab_hierarchy_callback, &args))
		goto bad;

	if (check_cond_avtab_hierarchy(p->cond_list, &args))
		goto bad;

	if (hashtab_map(p->p_roles.table, check_role_hierarchy_callback, &args))
		goto bad;

	if (hashtab_map(p->p_users.table, check_user_hierarchy_callback, &args))
		goto bad;

	if (args.numerr) {
		ERR(handle, "%d total errors found during hierarchy check",
		    args.numerr);
		goto bad;
	}

	avtab_destroy(&expa);
	return 0;

      bad:
	avtab_destroy(&expa);
	return -1;

      oom:
	ERR(handle, "Out of memory");
	return -1;
}
