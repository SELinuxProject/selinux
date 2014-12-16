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

static void report_failure(sepol_handle_t *handle, policydb_t *p,
			   const avrule_t * avrule,
			   unsigned int stype, unsigned int ttype,
			   const class_perm_node_t *curperm,
			   const avtab_ptr_t node)
{
	if (avrule->source_filename) {
		ERR(handle, "neverallow on line %lu of %s (or line %lu of policy.conf) violated by allow %s %s:%s {%s };",
		    avrule->source_line, avrule->source_filename, avrule->line,
		    p->p_type_val_to_name[stype],
		    p->p_type_val_to_name[ttype],
		    p->p_class_val_to_name[curperm->tclass - 1],
		    sepol_av_to_string(p, curperm->tclass,
				       node->datum.data & curperm->data));
	} else if (avrule->line) {
		ERR(handle, "neverallow on line %lu violated by allow %s %s:%s {%s };",
		    avrule->line, p->p_type_val_to_name[stype],
		    p->p_type_val_to_name[ttype],
		    p->p_class_val_to_name[curperm->tclass - 1],
		    sepol_av_to_string(p, curperm->tclass,
				       node->datum.data & curperm->data));
	} else {
		ERR(handle, "neverallow violated by allow %s %s:%s {%s };",
		    p->p_type_val_to_name[stype],
		    p->p_type_val_to_name[ttype],
		    p->p_class_val_to_name[curperm->tclass - 1],
		    sepol_av_to_string(p, curperm->tclass,
				       node->datum.data & curperm->data));
	}
}

static unsigned long check_assertion_helper(sepol_handle_t * handle,
				  policydb_t * p,
				  avtab_t * te_avtab, avtab_t * te_cond_avtab,
				  unsigned int stype, unsigned int ttype,
				  const avrule_t * avrule)
{
	avtab_key_t avkey;
	avtab_ptr_t node;
	class_perm_node_t *curperm;
	unsigned long errors = 0;

	for (curperm = avrule->perms; curperm != NULL; curperm = curperm->next) {
		avkey.source_type = stype + 1;
		avkey.target_type = ttype + 1;
		avkey.target_class = curperm->tclass;
		avkey.specified = AVTAB_ALLOWED;
		for (node = avtab_search_node(te_avtab, &avkey);
		     node != NULL;
		     node = avtab_search_node_next(node, avkey.specified)) {
			if (node->datum.data & curperm->data) {
				report_failure(handle, p, avrule, stype, ttype, curperm, node);
				errors++;
			}
		}
		for (node = avtab_search_node(te_cond_avtab, &avkey);
		     node != NULL;
		     node = avtab_search_node_next(node, avkey.specified)) {
			if (node->datum.data & curperm->data) {
				report_failure(handle, p, avrule, stype, ttype, curperm, node);
				errors++;
			}
		}
	}

	return errors;
}

int check_assertions(sepol_handle_t * handle, policydb_t * p,
		     avrule_t * avrules)
{
	avrule_t *a;
	avtab_t te_avtab, te_cond_avtab;
	ebitmap_node_t *snode, *tnode;
	unsigned int i, j;
	unsigned long errors = 0;

	if (!avrules) {
		/* Since assertions are stored in avrules, if it is NULL
		   there won't be any to check. This also prevents an invalid
		   free if the avtabs are never initialized */
		return 0;
	}

	if (avrules) {
		if (avtab_init(&te_avtab))
			goto oom;
		if (avtab_init(&te_cond_avtab)) {
			avtab_destroy(&te_avtab);
			goto oom;
		}
		if (expand_avtab(p, &p->te_avtab, &te_avtab) ||
		    expand_avtab(p, &p->te_cond_avtab, &te_cond_avtab)) {
			avtab_destroy(&te_avtab);
			avtab_destroy(&te_cond_avtab);
			goto oom;
		}
	}

	for (a = avrules; a != NULL; a = a->next) {
		ebitmap_t *stypes = &a->stypes.types;
		ebitmap_t *ttypes = &a->ttypes.types;

		if (!(a->specified & AVRULE_NEVERALLOW))
			continue;

		ebitmap_for_each_bit(stypes, snode, i) {
			if (!ebitmap_node_get_bit(snode, i))
				continue;
			if (a->flags & RULE_SELF) {
				errors += check_assertion_helper
				    (handle, p, &te_avtab, &te_cond_avtab, i, i,
				     a);
			}
			ebitmap_for_each_bit(ttypes, tnode, j) {
				if (!ebitmap_node_get_bit(tnode, j))
					continue;
				errors += check_assertion_helper
				    (handle, p, &te_avtab, &te_cond_avtab, i, j,
				     a);
			}
		}
	}

	if (errors)
		ERR(handle, "%lu neverallow failures occurred", errors);

	avtab_destroy(&te_avtab);
	avtab_destroy(&te_cond_avtab);
	return errors ? -1 : 0;

      oom:
	ERR(handle, "Out of memory - unable to check neverallows");
	return -1;
}
