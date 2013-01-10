/* Authors: Joshua Brindle <jbrindle@tresys.com>
 * 	    Jason Tang <jtang@tresys.com>
 *
 * Updates: KaiGai Kohei <kaigai@ak.jp.nec.com>
 *          adds checks based on newer boundary facility.
 *
 * A set of utility functions that aid policy decision when dealing
 * with hierarchal namespaces.
 *
 * Copyright (C) 2005 Tresys Technology, LLC
 *
 * Copyright (c) 2008 NEC Corporation
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

/*
 * find_parent_(type|role|user)
 *
 * This function returns the parent datum of given XXX_datum_t
 * object or NULL, if it doesn't exist.
 *
 * If the given datum has a valid bounds, this function merely
 * returns the indicated object. Otherwise, it looks up the
 * parent based on the based hierarchy.
 */
#define find_parent_template(prefix)				\
int find_parent_##prefix(hierarchy_args_t *a,			\
			 prefix##_datum_t *datum,		\
			 prefix##_datum_t **parent)		\
{								\
	char *parent_name, *datum_name, *tmp;			\
								\
	if (datum->bounds)						\
		*parent = a->p->prefix##_val_to_struct[datum->bounds - 1]; \
	else {								\
		datum_name = a->p->p_##prefix##_val_to_name[datum->s.value - 1]; \
									\
		tmp = strrchr(datum_name, '.');				\
		/* no '.' means it has no parent */			\
		if (!tmp) {						\
			*parent = NULL;					\
			return 0;					\
		}							\
									\
		parent_name = strdup(datum_name);			\
		if (!parent_name)					\
			return -1;					\
		parent_name[tmp - datum_name] = '\0';			\
									\
		*parent = hashtab_search(a->p->p_##prefix##s.table, parent_name); \
		if (!*parent) {						\
			/* Orphan type/role/user */			\
			ERR(a->handle,					\
			    "%s doesn't exist, %s is an orphan",	\
			    parent_name,				\
			    a->p->p_##prefix##_val_to_name[datum->s.value - 1]); \
			free(parent_name);				\
			return -1;					\
		}							\
		free(parent_name);					\
	}								\
									\
	return 0;							\
}

static find_parent_template(type)
static find_parent_template(role)
static find_parent_template(user)

static void compute_avtab_datum(hierarchy_args_t *args,
				avtab_key_t *key,
				avtab_datum_t *result)
{
	avtab_datum_t *avdatp;
	uint32_t av = 0;

	avdatp = avtab_search(args->expa, key);
	if (avdatp)
		av = avdatp->data;
	if (args->opt_cond_list) {
		avdatp = cond_av_list_search(key, args->opt_cond_list);
		if (avdatp)
			av |= avdatp->data;
	}

	result->data = av;
}

/* This function verifies that the type passed in either has a parent or is in the 
 * root of the namespace, 0 on success, 1 on orphan and -1 on error
 */
static int check_type_hierarchy_callback(hashtab_key_t k, hashtab_datum_t d,
					 void *args)
{
	hierarchy_args_t *a;
	type_datum_t *t, *tp;

	a = (hierarchy_args_t *) args;
	t = (type_datum_t *) d;

	if (t->flavor == TYPE_ATTRIB) {
		/* It's an attribute, we don't care */
		return 0;
	}
	if (find_parent_type(a, t, &tp) < 0)
		return -1;

	if (tp && tp->flavor == TYPE_ATTRIB) {
		/* The parent is an attribute but the child isn't, not legal */
		ERR(a->handle, "type %s is a child of an attribute %s",
		    (char *) k, a->p->p_type_val_to_name[tp->s.value - 1]);
		a->numerr++;
		return -1;
	}
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
	avtab_key_t key;
	hierarchy_args_t *a = (hierarchy_args_t *) args;
	type_datum_t *s, *t1 = NULL, *t2 = NULL;
	avtab_datum_t av;

	if (!(k->specified & AVTAB_ALLOWED)) {
		/* This is not an allow rule, no checking done */
		return 0;
	}

	/* search for parent first */
	s = a->p->type_val_to_struct[k->source_type - 1];
	if (find_parent_type(a, s, &t1) < 0)
		return -1;
	if (t1) {
		/*
		 * search for access allowed between type 1's
		 * parent and type 2.
		 */
		key.source_type = t1->s.value;
		key.target_type = k->target_type;
		key.target_class = k->target_class;
		key.specified = AVTAB_ALLOWED;
		compute_avtab_datum(a, &key, &av);

		if ((av.data & d->data) == d->data)
			return 0;
	}

	/* next we try type 1 and type 2's parent */
	s = a->p->type_val_to_struct[k->target_type - 1];
	if (find_parent_type(a, s, &t2) < 0)
		return -1;
	if (t2) {
		/*
		 * search for access allowed between type 1 and
		 * type 2's parent.
		 */
		key.source_type = k->source_type;
		key.target_type = t2->s.value;
		key.target_class = k->target_class;
		key.specified = AVTAB_ALLOWED;
		compute_avtab_datum(a, &key, &av);

		if ((av.data & d->data) == d->data)
			return 0;
	}

	if (t1 && t2) {
		/*
                 * search for access allowed between type 1's parent
                 * and type 2's parent.
                 */
		key.source_type = t1->s.value;
		key.target_type = t2->s.value;
		key.target_class = k->target_class;
		key.specified = AVTAB_ALLOWED;
		compute_avtab_datum(a, &key, &av);

		if ((av.data & d->data) == d->data)
			return 0;
	}

	/*
	 * Neither one of these types have parents and 
	 * therefore the hierarchical constraint does not apply
	 */
	if (!t1 && !t2)
		return 0;

	/*
	 * At this point there is a violation of the hierarchal
	 * constraint, send error condition back
	 */
	ERR(a->handle,
	    "hierarchy violation between types %s and %s : %s { %s }",
	    a->p->p_type_val_to_name[k->source_type - 1],
	    a->p->p_type_val_to_name[k->target_type - 1],
	    a->p->p_class_val_to_name[k->target_class - 1],
	    sepol_av_to_string(a->p, k->target_class, d->data & ~av.data));
	a->numerr++;
	return 0;
}

/*
 * If same permissions are allowed for same combination of
 * source and target, we can evaluate them as unconditional
 * one.
 * See the following example. A_t type is bounds of B_t type,
 * so B_t can never have wider permissions then A_t.
 * A_t has conditional permission on X_t, however, a part of
 * them (getattr and read) are unconditionaly allowed to A_t.
 *
 * Example)
 * typebounds A_t B_t;
 *
 * allow B_t X_t : file { getattr };
 * if (foo_bool) {
 *     allow A_t X_t : file { getattr read };
 * } else {
 *     allow A_t X_t : file { getattr read write };
 * }
 *
 * We have to pull up them as unconditional ones in this case,
 * because it seems to us B_t is violated to bounds constraints
 * during unconditional policy checking.
 */
static int pullup_unconditional_perms(cond_list_t * cond_list,
				      hierarchy_args_t * args)
{
	cond_list_t *cur_node;
	cond_av_list_t *cur_av, *expl_true = NULL, *expl_false = NULL;
	avtab_t expa_true, expa_false;
	avtab_datum_t *avdatp;
	avtab_datum_t avdat;
	avtab_ptr_t avnode;

	for (cur_node = cond_list; cur_node; cur_node = cur_node->next) {
		if (avtab_init(&expa_true))
			goto oom0;
		if (avtab_init(&expa_false))
			goto oom1;
		if (expand_cond_av_list(args->p, cur_node->true_list,
					&expl_true, &expa_true))
			goto oom2;
		if (expand_cond_av_list(args->p, cur_node->false_list,
					&expl_false, &expa_false))
			goto oom3;
		for (cur_av = expl_true; cur_av; cur_av = cur_av->next) {
			avdatp = avtab_search(&expa_false,
					      &cur_av->node->key);
			if (!avdatp)
				continue;

			avdat.data = (cur_av->node->datum.data
				      & avdatp->data);
			if (!avdat.data)
				continue;

			avnode = avtab_search_node(args->expa,
						   &cur_av->node->key);
			if (avnode) {
				avnode->datum.data |= avdat.data;
			} else {
				if (avtab_insert(args->expa,
						 &cur_av->node->key,
						 &avdat))
					goto oom4;
			}
		}
		cond_av_list_destroy(expl_false);
		cond_av_list_destroy(expl_true);
		avtab_destroy(&expa_false);
		avtab_destroy(&expa_true);
	}
	return 0;

oom4:
	cond_av_list_destroy(expl_false);
oom3:
	cond_av_list_destroy(expl_true);
oom2:
	avtab_destroy(&expa_false);
oom1:
	avtab_destroy(&expa_true);
oom0:
	ERR(args->handle, "out of memory on conditional av list expansion");
        return 1;
}

static int check_cond_avtab_hierarchy(cond_list_t * cond_list,
				      hierarchy_args_t * args)
{
	int rc;
	cond_list_t *cur_node;
	cond_av_list_t *cur_av, *expl = NULL;
	avtab_t expa;
	hierarchy_args_t *a = (hierarchy_args_t *) args;
	avtab_datum_t avdat, *uncond;

	for (cur_node = cond_list; cur_node; cur_node = cur_node->next) {
		/*
		 * Check true condition
		 */
		if (avtab_init(&expa))
			goto oom;
		if (expand_cond_av_list(args->p, cur_node->true_list,
					&expl, &expa)) {
			avtab_destroy(&expa);
			goto oom;
		}
		args->opt_cond_list = expl;
		for (cur_av = expl; cur_av; cur_av = cur_av->next) {
			avdat.data = cur_av->node->datum.data;
			uncond = avtab_search(a->expa, &cur_av->node->key);
			if (uncond)
				avdat.data |= uncond->data;
			rc = check_avtab_hierarchy_callback(&cur_av->node->key,
							    &avdat, args);
			if (rc)
				args->numerr++;
		}
		cond_av_list_destroy(expl);
		avtab_destroy(&expa);

		/*
		 * Check false condition
		 */
		if (avtab_init(&expa))
			goto oom;
		if (expand_cond_av_list(args->p, cur_node->false_list,
					&expl, &expa)) {
			avtab_destroy(&expa);
			goto oom;
		}
		args->opt_cond_list = expl;
		for (cur_av = expl; cur_av; cur_av = cur_av->next) {
			avdat.data = cur_av->node->datum.data;
			uncond = avtab_search(a->expa, &cur_av->node->key);
			if (uncond)
				avdat.data |= uncond->data;

			rc = check_avtab_hierarchy_callback(&cur_av->node->key,
							    &avdat, args);
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
	hierarchy_args_t *a;
	role_datum_t *r, *rp;

	a = (hierarchy_args_t *) args;
	r = (role_datum_t *) d;

	if (find_parent_role(a, r, &rp) < 0)
		return -1;

	if (rp && !ebitmap_contains(&rp->types.types, &r->types.types)) {
		/* hierarchical constraint violation, return error */
		ERR(a->handle, "Role hierarchy violation, %s exceeds %s",
		    (char *) k, a->p->p_role_val_to_name[rp->s.value - 1]);
		a->numerr++;
	}
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
	hierarchy_args_t *a;
	user_datum_t *u, *up;

	a = (hierarchy_args_t *) args;
	u = (user_datum_t *) d;

	if (find_parent_user(a, u, &up) < 0)
		return -1;

	if (up && !ebitmap_contains(&up->roles.roles, &u->roles.roles)) {
		/* hierarchical constraint violation, return error */
		ERR(a->handle, "User hierarchy violation, %s exceeds %s",
		    (char *) k, a->p->p_user_val_to_name[up->s.value - 1]);
		a->numerr++;
	}
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

	if (pullup_unconditional_perms(p->cond_list, &args))
		return -1;

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
