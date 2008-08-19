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

static int check_assertion_helper(sepol_handle_t * handle,
				  policydb_t * p,
				  avtab_t * te_avtab, avtab_t * te_cond_avtab,
				  unsigned int stype, unsigned int ttype,
				  class_perm_node_t * perm, unsigned long line)
{
	avtab_key_t avkey;
	avtab_ptr_t node;
	class_perm_node_t *curperm;

	for (curperm = perm; curperm != NULL; curperm = curperm->next) {
		avkey.source_type = stype + 1;
		avkey.target_type = ttype + 1;
		avkey.target_class = curperm->class;
		avkey.specified = AVTAB_ALLOWED;
		for (node = avtab_search_node(te_avtab, &avkey);
		     node != NULL;
		     node = avtab_search_node_next(node, avkey.specified)) {
			if (node->datum.data & curperm->data)
				goto err;
		}
		for (node = avtab_search_node(te_cond_avtab, &avkey);
		     node != NULL;
		     node = avtab_search_node_next(node, avkey.specified)) {
			if (node->datum.data & curperm->data)
				goto err;
		}
	}

	return 0;

      err:
	if (line) {
		ERR(handle, "neverallow on line %lu violated by allow %s %s:%s {%s };",
		    line, p->p_type_val_to_name[stype], 
		    p->p_type_val_to_name[ttype],
		    p->p_class_val_to_name[curperm->class - 1],
		    sepol_av_to_string(p, curperm->class,
				       node->datum.data & curperm->data));
	} else {
		ERR(handle, "neverallow violated by allow %s %s:%s {%s };",
		    p->p_type_val_to_name[stype], 
		    p->p_type_val_to_name[ttype],
		    p->p_class_val_to_name[curperm->class - 1],
		    sepol_av_to_string(p, curperm->class,
				       node->datum.data & curperm->data));
	}
	return -1;
}

int check_assertions(sepol_handle_t * handle, policydb_t * p,
		     avrule_t * avrules)
{
	avrule_t *a;
	avtab_t te_avtab, te_cond_avtab;
	ebitmap_node_t *snode, *tnode;
	unsigned int i, j;
	int rc;

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
				if (check_assertion_helper
				    (handle, p, &te_avtab, &te_cond_avtab, i, i,
				     a->perms, a->line)) {
					rc = -1;
					goto out;
				}
			}
			ebitmap_for_each_bit(ttypes, tnode, j) {
				if (!ebitmap_node_get_bit(tnode, j))
					continue;
				if (check_assertion_helper
				    (handle, p, &te_avtab, &te_cond_avtab, i, j,
				     a->perms, a->line)) {
					rc = -1;
					goto out;
				}
			}
		}
	}

	rc = 0;
out:
	avtab_destroy(&te_avtab);
	avtab_destroy(&te_cond_avtab);
	return rc;

      oom:
	ERR(handle, "Out of memory - unable to check neverallows");
	return -1;
}
