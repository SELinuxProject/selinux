/* Authors: Joshua Brindle <jbrindle@tresys.com>
 *              
 * Assertion checker for avtab entries, taken from 
 * checkpolicy.c by Stephen Smalley <sds@tycho.nsa.gov>
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

#include <sepol/policydb/avtab.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/expand.h>
#include <sepol/policydb/util.h>

#include "debug.h"

struct avtab_match_args {
	sepol_handle_t *handle;
	policydb_t *p;
	avrule_t *avrule;
	unsigned long errors;
};

static void report_failure(sepol_handle_t *handle, policydb_t *p, const avrule_t *avrule,
			   unsigned int stype, unsigned int ttype,
			   const class_perm_node_t *curperm, uint32_t perms)
{
	if (avrule->source_filename) {
		ERR(handle, "neverallow on line %lu of %s (or line %lu of policy.conf) violated by allow %s %s:%s {%s };",
		    avrule->source_line, avrule->source_filename, avrule->line,
		    p->p_type_val_to_name[stype],
		    p->p_type_val_to_name[ttype],
		    p->p_class_val_to_name[curperm->tclass - 1],
		    sepol_av_to_string(p, curperm->tclass, perms));
	} else if (avrule->line) {
		ERR(handle, "neverallow on line %lu violated by allow %s %s:%s {%s };",
		    avrule->line, p->p_type_val_to_name[stype],
		    p->p_type_val_to_name[ttype],
		    p->p_class_val_to_name[curperm->tclass - 1],
		    sepol_av_to_string(p, curperm->tclass, perms));
	} else {
		ERR(handle, "neverallow violated by allow %s %s:%s {%s };",
		    p->p_type_val_to_name[stype],
		    p->p_type_val_to_name[ttype],
		    p->p_class_val_to_name[curperm->tclass - 1],
		    sepol_av_to_string(p, curperm->tclass, perms));
	}
}

static int match_any_class_permissions(class_perm_node_t *cp, uint32_t class, uint32_t data)
{
	for (; cp; cp = cp->next) {
		if ((cp->tclass == class) && (cp->data & data)) {
			break;
		}
	}
	if (!cp)
		return 0;

	return 1;
}


static int report_assertion_avtab_matches(avtab_key_t *k, avtab_datum_t *d, void *args)
{
	int rc = 0;
	struct avtab_match_args *a = (struct avtab_match_args *)args;
	sepol_handle_t *handle = a->handle;
	policydb_t *p = a->p;
	avrule_t *avrule = a->avrule;
	class_perm_node_t *cp;
	uint32_t perms;
	ebitmap_t src_matches, tgt_matches, matches;
	ebitmap_node_t *snode, *tnode;
	unsigned int i, j;

	if (k->specified != AVTAB_ALLOWED)
		return 0;

	if (!match_any_class_permissions(avrule->perms, k->target_class, d->data))
		return 0;

	ebitmap_init(&src_matches);
	ebitmap_init(&tgt_matches);
	ebitmap_init(&matches);

	rc = ebitmap_and(&src_matches, &avrule->stypes.types,
			 &p->attr_type_map[k->source_type - 1]);
	if (rc)
		goto oom;

	if (ebitmap_length(&src_matches) == 0)
		goto exit;

	if (avrule->flags == RULE_SELF) {
		rc = ebitmap_and(&matches, &p->attr_type_map[k->source_type - 1], &p->attr_type_map[k->target_type - 1]);
		if (rc)
			goto oom;
		rc = ebitmap_and(&tgt_matches, &avrule->stypes.types, &matches);
		if (rc)
			goto oom;
	} else {
		rc = ebitmap_and(&tgt_matches, &avrule->ttypes.types, &p->attr_type_map[k->target_type -1]);
		if (rc)
			goto oom;
	}

	if (ebitmap_length(&tgt_matches) == 0)
		goto exit;

	for (cp = avrule->perms; cp; cp = cp->next) {
		perms = cp->data & d->data;
		if ((cp->tclass != k->target_class) || !perms) {
			continue;
		}

		ebitmap_for_each_bit(&src_matches, snode, i) {
			if (!ebitmap_node_get_bit(snode, i))
				continue;
			ebitmap_for_each_bit(&tgt_matches, tnode, j) {
				if (!ebitmap_node_get_bit(tnode, j))
					continue;
				a->errors++;
				report_failure(handle, p, avrule, i, j, cp, perms);
			}
		}
	}

	goto exit;

oom:
	ERR(NULL, "Out of memory - unable to check neverallows");

exit:
	ebitmap_destroy(&src_matches);
	ebitmap_destroy(&tgt_matches);
	ebitmap_destroy(&matches);
	return rc;
}

int report_assertion_failures(sepol_handle_t *handle, policydb_t *p, avrule_t *avrule)
{
	int rc;
	struct avtab_match_args args;

	args.handle = handle;
	args.p = p;
	args.avrule = avrule;
	args.errors = 0;

	rc = avtab_map(&p->te_avtab, report_assertion_avtab_matches, &args);
	if (rc)
		goto oom;

	rc = avtab_map(&p->te_cond_avtab, report_assertion_avtab_matches, &args);
	if (rc)
		goto oom;

	return args.errors;

oom:
	return rc;
}

static int check_assertion_avtab_match(avtab_key_t *k, avtab_datum_t *d, void *args)
{
	int rc;
	struct avtab_match_args *a = (struct avtab_match_args *)args;
	policydb_t *p = a->p;
	avrule_t *avrule = a->avrule;

	if (k->specified != AVTAB_ALLOWED)
		goto exit;

	if (!match_any_class_permissions(avrule->perms, k->target_class, d->data))
		goto exit;

	rc = ebitmap_match_any(&avrule->stypes.types, &p->attr_type_map[k->source_type - 1]);
	if (rc == 0)
		goto exit;

	if (avrule->flags == RULE_SELF) {
		/* If the neverallow uses SELF, then it is not enough that the
		 * neverallow's source matches the src and tgt of the rule being checked.
		 * It must match the same thing in the src and tgt, so AND the source
		 * and target together and check for a match on the result.
		 */
		ebitmap_t match;
		rc = ebitmap_and(&match, &p->attr_type_map[k->source_type - 1], &p->attr_type_map[k->target_type - 1] );
		if (rc) {
			ebitmap_destroy(&match);
			goto oom;
		}
		rc = ebitmap_match_any(&avrule->stypes.types, &match);
		ebitmap_destroy(&match);
	} else {
		rc = ebitmap_match_any(&avrule->ttypes.types, &p->attr_type_map[k->target_type -1]);
	}
	if (rc == 0)
		goto exit;

	return 1;

exit:
	return 0;

oom:
	ERR(NULL, "Out of memory - unable to check neverallows");
	return rc;
}

int check_assertion(policydb_t *p, avrule_t *avrule)
{
	int rc;
	struct avtab_match_args args;

	args.handle = NULL;
	args.p = p;
	args.avrule = avrule;
	args.errors = 0;

	rc = avtab_map(&p->te_avtab, check_assertion_avtab_match, &args);

	if (rc == 0) {
		rc = avtab_map(&p->te_cond_avtab, check_assertion_avtab_match, &args);
	}

	return rc;
}

int check_assertions(sepol_handle_t * handle, policydb_t * p,
		     avrule_t * avrules)
{
	int rc;
	avrule_t *a;
	unsigned long errors = 0;

	if (!avrules) {
		/* Since assertions are stored in avrules, if it is NULL
		   there won't be any to check. This also prevents an invalid
		   free if the avtabs are never initialized */
		return 0;
	}

	for (a = avrules; a != NULL; a = a->next) {
		if (!(a->specified & AVRULE_NEVERALLOW))
			continue;
		rc = check_assertion(p, a);
		if (rc) {
			rc = report_assertion_failures(handle, p, a);
			if (rc < 0) {
				ERR(handle, "Error occurred while checking neverallows");
				return -1;
			}
			errors += rc;
		}
	}

	if (errors)
		ERR(handle, "%lu neverallow failures occurred", errors);

	return errors ? -1 : 0;
}
