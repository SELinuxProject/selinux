
/*
 * Author : Stephen Smalley, <sds@epoch.ncsc.mil> 
 */
/*
 * Updated: Trusted Computer Solutions, Inc. <dgoeddel@trustedcs.com>
 *
 *	Support for enhanced MLS infrastructure.
 *
 * Updated: Frank Mayer <mayerf@tresys.com>
 *          and Karl MacMillan <kmacmillan@tresys.com>
 *
 * 	Added conditional policy language extensions
 *
 * Updated: Red Hat, Inc.  James Morris <jmorris@redhat.com>
 *
 *      Fine-grained netlink support
 *      IPv6 support
 *      Code cleanup
 *
 * Copyright (C) 2004-2005 Trusted Computer Solutions, Inc.
 * Copyright (C) 2003 - 2004 Tresys Technology, LLC
 * Copyright (C) 2003 - 2004 Red Hat, Inc.
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

/* FLASK */

/*
 * Implementation of the security services.
 */

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sepol/policydb/policydb.h>
#include <sepol/policydb/sidtab.h>
#include <sepol/policydb/services.h>
#include <sepol/policydb/conditional.h>
#include <sepol/policydb/flask.h>

#include "debug.h"
#include "private.h"
#include "context.h"
#include "av_permissions.h"
#include "dso.h"
#include "mls.h"

#define BUG() do { ERR(NULL, "Badness at %s:%d", __FILE__, __LINE__); } while (0)
#define BUG_ON(x) do { if (x) ERR(NULL, "Badness at %s:%d", __FILE__, __LINE__); } while (0)

static int selinux_enforcing = 1;

static sidtab_t mysidtab, *sidtab = &mysidtab;
static policydb_t mypolicydb, *policydb = &mypolicydb;

int hidden sepol_set_sidtab(sidtab_t * s)
{
	sidtab = s;
	return 0;
}

int hidden sepol_set_policydb(policydb_t * p)
{
	policydb = p;
	return 0;
}

int sepol_set_policydb_from_file(FILE * fp)
{
	struct policy_file pf;

	policy_file_init(&pf);
	pf.fp = fp;
	pf.type = PF_USE_STDIO;
	if (mypolicydb.policy_type)
		policydb_destroy(&mypolicydb);
	if (policydb_init(&mypolicydb)) {
		ERR(NULL, "Out of memory!");
		return -1;
	}
	if (policydb_read(&mypolicydb, &pf, 0)) {
		ERR(NULL, "can't read binary policy: %s", strerror(errno));
		return -1;
	}
	policydb = &mypolicydb;
	return sepol_sidtab_init(sidtab);
}

/*
 * The largest sequence number that has been used when
 * providing an access decision to the access vector cache.
 * The sequence number only changes when a policy change
 * occurs.
 */
static uint32_t latest_granting = 0;

/*
 * Return the boolean value of a constraint expression 
 * when it is applied to the specified source and target 
 * security contexts.
 *
 * xcontext is a special beast...  It is used by the validatetrans rules
 * only.  For these rules, scontext is the context before the transition,
 * tcontext is the context after the transition, and xcontext is the context
 * of the process performing the transition.  All other callers of
 * constraint_expr_eval should pass in NULL for xcontext.
 */
static int constraint_expr_eval(context_struct_t * scontext,
				context_struct_t * tcontext,
				context_struct_t * xcontext,
				constraint_expr_t * cexpr)
{
	uint32_t val1, val2;
	context_struct_t *c;
	role_datum_t *r1, *r2;
	mls_level_t *l1, *l2;
	constraint_expr_t *e;
	int s[CEXPR_MAXDEPTH];
	int sp = -1;

	for (e = cexpr; e; e = e->next) {
		switch (e->expr_type) {
		case CEXPR_NOT:
			BUG_ON(sp < 0);
			s[sp] = !s[sp];
			break;
		case CEXPR_AND:
			BUG_ON(sp < 1);
			sp--;
			s[sp] &= s[sp + 1];
			break;
		case CEXPR_OR:
			BUG_ON(sp < 1);
			sp--;
			s[sp] |= s[sp + 1];
			break;
		case CEXPR_ATTR:
			if (sp == (CEXPR_MAXDEPTH - 1))
				return 0;
			switch (e->attr) {
			case CEXPR_USER:
				val1 = scontext->user;
				val2 = tcontext->user;
				break;
			case CEXPR_TYPE:
				val1 = scontext->type;
				val2 = tcontext->type;
				break;
			case CEXPR_ROLE:
				val1 = scontext->role;
				val2 = tcontext->role;
				r1 = policydb->role_val_to_struct[val1 - 1];
				r2 = policydb->role_val_to_struct[val2 - 1];
				switch (e->op) {
				case CEXPR_DOM:
					s[++sp] =
					    ebitmap_get_bit(&r1->dominates,
							    val2 - 1);
					continue;
				case CEXPR_DOMBY:
					s[++sp] =
					    ebitmap_get_bit(&r2->dominates,
							    val1 - 1);
					continue;
				case CEXPR_INCOMP:
					s[++sp] =
					    (!ebitmap_get_bit
					     (&r1->dominates, val2 - 1)
					     && !ebitmap_get_bit(&r2->dominates,
								 val1 - 1));
					continue;
				default:
					break;
				}
				break;
			case CEXPR_L1L2:
				l1 = &(scontext->range.level[0]);
				l2 = &(tcontext->range.level[0]);
				goto mls_ops;
			case CEXPR_L1H2:
				l1 = &(scontext->range.level[0]);
				l2 = &(tcontext->range.level[1]);
				goto mls_ops;
			case CEXPR_H1L2:
				l1 = &(scontext->range.level[1]);
				l2 = &(tcontext->range.level[0]);
				goto mls_ops;
			case CEXPR_H1H2:
				l1 = &(scontext->range.level[1]);
				l2 = &(tcontext->range.level[1]);
				goto mls_ops;
			case CEXPR_L1H1:
				l1 = &(scontext->range.level[0]);
				l2 = &(scontext->range.level[1]);
				goto mls_ops;
			case CEXPR_L2H2:
				l1 = &(tcontext->range.level[0]);
				l2 = &(tcontext->range.level[1]);
				goto mls_ops;
			      mls_ops:
				switch (e->op) {
				case CEXPR_EQ:
					s[++sp] = mls_level_eq(l1, l2);
					continue;
				case CEXPR_NEQ:
					s[++sp] = !mls_level_eq(l1, l2);
					continue;
				case CEXPR_DOM:
					s[++sp] = mls_level_dom(l1, l2);
					continue;
				case CEXPR_DOMBY:
					s[++sp] = mls_level_dom(l2, l1);
					continue;
				case CEXPR_INCOMP:
					s[++sp] = mls_level_incomp(l2, l1);
					continue;
				default:
					BUG();
					return 0;
				}
				break;
			default:
				BUG();
				return 0;
			}

			switch (e->op) {
			case CEXPR_EQ:
				s[++sp] = (val1 == val2);
				break;
			case CEXPR_NEQ:
				s[++sp] = (val1 != val2);
				break;
			default:
				BUG();
				return 0;
			}
			break;
		case CEXPR_NAMES:
			if (sp == (CEXPR_MAXDEPTH - 1))
				return 0;
			c = scontext;
			if (e->attr & CEXPR_TARGET)
				c = tcontext;
			else if (e->attr & CEXPR_XTARGET) {
				c = xcontext;
				if (!c) {
					BUG();
					return 0;
				}
			}
			if (e->attr & CEXPR_USER)
				val1 = c->user;
			else if (e->attr & CEXPR_ROLE)
				val1 = c->role;
			else if (e->attr & CEXPR_TYPE)
				val1 = c->type;
			else {
				BUG();
				return 0;
			}

			switch (e->op) {
			case CEXPR_EQ:
				s[++sp] = ebitmap_get_bit(&e->names, val1 - 1);
				break;
			case CEXPR_NEQ:
				s[++sp] = !ebitmap_get_bit(&e->names, val1 - 1);
				break;
			default:
				BUG();
				return 0;
			}
			break;
		default:
			BUG();
			return 0;
		}
	}

	BUG_ON(sp != 0);
	return s[0];
}

/*
 * Compute access vectors based on a context structure pair for
 * the permissions in a particular class.
 */
static int context_struct_compute_av(context_struct_t * scontext,
				     context_struct_t * tcontext,
				     sepol_security_class_t tclass,
				     sepol_access_vector_t requested,
				     struct sepol_av_decision *avd,
				     unsigned int *reason)
{
	constraint_node_t *constraint;
	struct role_allow *ra;
	avtab_key_t avkey;
	class_datum_t *tclass_datum;
	avtab_ptr_t node;
	ebitmap_t *sattr, *tattr;
	ebitmap_node_t *snode, *tnode;
	unsigned int i, j;

	if (!tclass || tclass > policydb->p_classes.nprim) {
		ERR(NULL, "unrecognized class %d", tclass);
		return -EINVAL;
	}
	tclass_datum = policydb->class_val_to_struct[tclass - 1];

	/* 
	 * Initialize the access vectors to the default values.
	 */
	avd->allowed = 0;
	avd->decided = 0xffffffff;
	avd->auditallow = 0;
	avd->auditdeny = 0xffffffff;
	avd->seqno = latest_granting;
	*reason = 0;

	/*
	 * If a specific type enforcement rule was defined for
	 * this permission check, then use it.
	 */
	avkey.target_class = tclass;
	avkey.specified = AVTAB_AV;
	sattr = &policydb->type_attr_map[scontext->type - 1];
	tattr = &policydb->type_attr_map[tcontext->type - 1];
	ebitmap_for_each_bit(sattr, snode, i) {
		if (!ebitmap_node_get_bit(snode, i))
			continue;
		ebitmap_for_each_bit(tattr, tnode, j) {
			if (!ebitmap_node_get_bit(tnode, j))
				continue;
			avkey.source_type = i + 1;
			avkey.target_type = j + 1;
			for (node =
			     avtab_search_node(&policydb->te_avtab, &avkey);
			     node != NULL;
			     node =
			     avtab_search_node_next(node, avkey.specified)) {
				if (node->key.specified == AVTAB_ALLOWED)
					avd->allowed |= node->datum.data;
				else if (node->key.specified ==
					 AVTAB_AUDITALLOW)
					avd->auditallow |= node->datum.data;
				else if (node->key.specified == AVTAB_AUDITDENY)
					avd->auditdeny &= node->datum.data;
			}

			/* Check conditional av table for additional permissions */
			cond_compute_av(&policydb->te_cond_avtab, &avkey, avd);

		}
	}

	if (requested & ~avd->allowed) {
		*reason |= SEPOL_COMPUTEAV_TE;
		requested &= avd->allowed;
	}

	/* 
	 * Remove any permissions prohibited by a constraint (this includes
	 * the MLS policy).
	 */
	constraint = tclass_datum->constraints;
	while (constraint) {
		if ((constraint->permissions & (avd->allowed)) &&
		    !constraint_expr_eval(scontext, tcontext, NULL,
					  constraint->expr)) {
			avd->allowed =
			    (avd->allowed) & ~(constraint->permissions);
		}
		constraint = constraint->next;
	}

	if (requested & ~avd->allowed) {
		*reason |= SEPOL_COMPUTEAV_CONS;
		requested &= avd->allowed;
	}

	/* 
	 * If checking process transition permission and the
	 * role is changing, then check the (current_role, new_role) 
	 * pair.
	 */
	if (tclass == SECCLASS_PROCESS &&
	    (avd->allowed & (PROCESS__TRANSITION | PROCESS__DYNTRANSITION)) &&
	    scontext->role != tcontext->role) {
		for (ra = policydb->role_allow; ra; ra = ra->next) {
			if (scontext->role == ra->role &&
			    tcontext->role == ra->new_role)
				break;
		}
		if (!ra)
			avd->allowed = (avd->allowed) & ~(PROCESS__TRANSITION |
							  PROCESS__DYNTRANSITION);
	}

	if (requested & ~avd->allowed) {
		*reason |= SEPOL_COMPUTEAV_RBAC;
		requested &= avd->allowed;
	}

	return 0;
}

int hidden sepol_validate_transition(sepol_security_id_t oldsid,
				     sepol_security_id_t newsid,
				     sepol_security_id_t tasksid,
				     sepol_security_class_t tclass)
{
	context_struct_t *ocontext;
	context_struct_t *ncontext;
	context_struct_t *tcontext;
	class_datum_t *tclass_datum;
	constraint_node_t *constraint;

	if (!tclass || tclass > policydb->p_classes.nprim) {
		ERR(NULL, "unrecognized class %d", tclass);
		return -EINVAL;
	}
	tclass_datum = policydb->class_val_to_struct[tclass - 1];

	ocontext = sepol_sidtab_search(sidtab, oldsid);
	if (!ocontext) {
		ERR(NULL, "unrecognized SID %d", oldsid);
		return -EINVAL;
	}

	ncontext = sepol_sidtab_search(sidtab, newsid);
	if (!ncontext) {
		ERR(NULL, "unrecognized SID %d", newsid);
		return -EINVAL;
	}

	tcontext = sepol_sidtab_search(sidtab, tasksid);
	if (!tcontext) {
		ERR(NULL, "unrecognized SID %d", tasksid);
		return -EINVAL;
	}

	constraint = tclass_datum->validatetrans;
	while (constraint) {
		if (!constraint_expr_eval(ocontext, ncontext, tcontext,
					  constraint->expr)) {
			return -EPERM;
		}
		constraint = constraint->next;
	}

	return 0;
}

int hidden sepol_compute_av_reason(sepol_security_id_t ssid,
				   sepol_security_id_t tsid,
				   sepol_security_class_t tclass,
				   sepol_access_vector_t requested,
				   struct sepol_av_decision *avd,
				   unsigned int *reason)
{
	context_struct_t *scontext = 0, *tcontext = 0;
	int rc = 0;

	scontext = sepol_sidtab_search(sidtab, ssid);
	if (!scontext) {
		ERR(NULL, "unrecognized SID %d", ssid);
		rc = -EINVAL;
		goto out;
	}
	tcontext = sepol_sidtab_search(sidtab, tsid);
	if (!tcontext) {
		ERR(NULL, "unrecognized SID %d", tsid);
		rc = -EINVAL;
		goto out;
	}

	rc = context_struct_compute_av(scontext, tcontext, tclass,
				       requested, avd, reason);
      out:
	return rc;
}

int hidden sepol_compute_av(sepol_security_id_t ssid,
			    sepol_security_id_t tsid,
			    sepol_security_class_t tclass,
			    sepol_access_vector_t requested,
			    struct sepol_av_decision *avd)
{
	unsigned int reason = 0;
	return sepol_compute_av_reason(ssid, tsid, tclass, requested, avd,
				       &reason);
}

/*
 * Write the security context string representation of 
 * the context associated with `sid' into a dynamically
 * allocated string of the correct size.  Set `*scontext'
 * to point to this string and set `*scontext_len' to
 * the length of the string.
 */
int hidden sepol_sid_to_context(sepol_security_id_t sid,
				sepol_security_context_t * scontext,
				size_t * scontext_len)
{
	context_struct_t *context;
	int rc = 0;

	context = sepol_sidtab_search(sidtab, sid);
	if (!context) {
		ERR(NULL, "unrecognized SID %d", sid);
		rc = -EINVAL;
		goto out;
	}
	rc = context_to_string(NULL, policydb, context, scontext, scontext_len);
      out:
	return rc;

}

/*
 * Return a SID associated with the security context that
 * has the string representation specified by `scontext'.
 */
int hidden sepol_context_to_sid(const sepol_security_context_t scontext,
				size_t scontext_len, sepol_security_id_t * sid)
{

	context_struct_t *context = NULL;

	/* First, create the context */
	if (context_from_string(NULL, policydb, &context,
				scontext, scontext_len) < 0)
		goto err;

	/* Obtain the new sid */
	if (sid && (sepol_sidtab_context_to_sid(sidtab, context, sid) < 0))
		goto err;

	context_destroy(context);
	free(context);
	return STATUS_SUCCESS;

      err:
	if (context) {
		context_destroy(context);
		free(context);
	}
	ERR(NULL, "could not convert %s to sid", scontext);
	return STATUS_ERR;
}

static inline int compute_sid_handle_invalid_context(context_struct_t *
						     scontext,
						     context_struct_t *
						     tcontext,
						     sepol_security_class_t
						     tclass,
						     context_struct_t *
						     newcontext)
{
	if (selinux_enforcing) {
		return -EACCES;
	} else {
		sepol_security_context_t s, t, n;
		size_t slen, tlen, nlen;

		context_to_string(NULL, policydb, scontext, &s, &slen);
		context_to_string(NULL, policydb, tcontext, &t, &tlen);
		context_to_string(NULL, policydb, newcontext, &n, &nlen);
		ERR(NULL, "invalid context %s for "
		    "scontext=%s tcontext=%s tclass=%s",
		    n, s, t, policydb->p_class_val_to_name[tclass - 1]);
		free(s);
		free(t);
		free(n);
		return 0;
	}
}

static int sepol_compute_sid(sepol_security_id_t ssid,
			     sepol_security_id_t tsid,
			     sepol_security_class_t tclass,
			     uint32_t specified, sepol_security_id_t * out_sid)
{
	context_struct_t *scontext = 0, *tcontext = 0, newcontext;
	struct role_trans *roletr = 0;
	avtab_key_t avkey;
	avtab_datum_t *avdatum;
	avtab_ptr_t node;
	int rc = 0;

	scontext = sepol_sidtab_search(sidtab, ssid);
	if (!scontext) {
		ERR(NULL, "unrecognized SID %d", ssid);
		rc = -EINVAL;
		goto out;
	}
	tcontext = sepol_sidtab_search(sidtab, tsid);
	if (!tcontext) {
		ERR(NULL, "unrecognized SID %d", tsid);
		rc = -EINVAL;
		goto out;
	}

	context_init(&newcontext);

	/* Set the user identity. */
	switch (specified) {
	case AVTAB_TRANSITION:
	case AVTAB_CHANGE:
		/* Use the process user identity. */
		newcontext.user = scontext->user;
		break;
	case AVTAB_MEMBER:
		/* Use the related object owner. */
		newcontext.user = tcontext->user;
		break;
	}

	/* Set the role and type to default values. */
	switch (tclass) {
	case SECCLASS_PROCESS:
		/* Use the current role and type of process. */
		newcontext.role = scontext->role;
		newcontext.type = scontext->type;
		break;
	default:
		/* Use the well-defined object role. */
		newcontext.role = OBJECT_R_VAL;
		/* Use the type of the related object. */
		newcontext.type = tcontext->type;
	}

	/* Look for a type transition/member/change rule. */
	avkey.source_type = scontext->type;
	avkey.target_type = tcontext->type;
	avkey.target_class = tclass;
	avkey.specified = specified;
	avdatum = avtab_search(&policydb->te_avtab, &avkey);

	/* If no permanent rule, also check for enabled conditional rules */
	if (!avdatum) {
		node = avtab_search_node(&policydb->te_cond_avtab, &avkey);
		for (; node != NULL;
		     node = avtab_search_node_next(node, specified)) {
			if (node->key.specified & AVTAB_ENABLED) {
				avdatum = &node->datum;
				break;
			}
		}
	}

	if (avdatum) {
		/* Use the type from the type transition/member/change rule. */
		newcontext.type = avdatum->data;
	}

	/* Check for class-specific changes. */
	switch (tclass) {
	case SECCLASS_PROCESS:
		if (specified & AVTAB_TRANSITION) {
			/* Look for a role transition rule. */
			for (roletr = policydb->role_tr; roletr;
			     roletr = roletr->next) {
				if (roletr->role == scontext->role &&
				    roletr->type == tcontext->type) {
					/* Use the role transition rule. */
					newcontext.role = roletr->new_role;
					break;
				}
			}
		}
		break;
	default:
		break;
	}

	/* Set the MLS attributes.
	   This is done last because it may allocate memory. */
	rc = mls_compute_sid(policydb, scontext, tcontext, tclass, specified,
			     &newcontext);
	if (rc)
		goto out;

	/* Check the validity of the context. */
	if (!policydb_context_isvalid(policydb, &newcontext)) {
		rc = compute_sid_handle_invalid_context(scontext,
							tcontext,
							tclass, &newcontext);
		if (rc)
			goto out;
	}
	/* Obtain the sid for the context. */
	rc = sepol_sidtab_context_to_sid(sidtab, &newcontext, out_sid);
      out:
	context_destroy(&newcontext);
	return rc;
}

/*
 * Compute a SID to use for labeling a new object in the 
 * class `tclass' based on a SID pair.  
 */
int hidden sepol_transition_sid(sepol_security_id_t ssid,
				sepol_security_id_t tsid,
				sepol_security_class_t tclass,
				sepol_security_id_t * out_sid)
{
	return sepol_compute_sid(ssid, tsid, tclass, AVTAB_TRANSITION, out_sid);
}

/*
 * Compute a SID to use when selecting a member of a 
 * polyinstantiated object of class `tclass' based on 
 * a SID pair.
 */
int hidden sepol_member_sid(sepol_security_id_t ssid,
			    sepol_security_id_t tsid,
			    sepol_security_class_t tclass,
			    sepol_security_id_t * out_sid)
{
	return sepol_compute_sid(ssid, tsid, tclass, AVTAB_MEMBER, out_sid);
}

/*
 * Compute a SID to use for relabeling an object in the 
 * class `tclass' based on a SID pair.  
 */
int hidden sepol_change_sid(sepol_security_id_t ssid,
			    sepol_security_id_t tsid,
			    sepol_security_class_t tclass,
			    sepol_security_id_t * out_sid)
{
	return sepol_compute_sid(ssid, tsid, tclass, AVTAB_CHANGE, out_sid);
}

/*
 * Verify that each permission that is defined under the
 * existing policy is still defined with the same value
 * in the new policy.
 */
static int validate_perm(hashtab_key_t key, hashtab_datum_t datum, void *p)
{
	hashtab_t h;
	perm_datum_t *perdatum, *perdatum2;

	h = (hashtab_t) p;
	perdatum = (perm_datum_t *) datum;

	perdatum2 = (perm_datum_t *) hashtab_search(h, key);
	if (!perdatum2) {
		ERR(NULL, "permission %s disappeared", key);
		return -1;
	}
	if (perdatum->s.value != perdatum2->s.value) {
		ERR(NULL, "the value of permissions %s changed", key);
		return -1;
	}
	return 0;
}

/*
 * Verify that each class that is defined under the
 * existing policy is still defined with the same 
 * attributes in the new policy.
 */
static int validate_class(hashtab_key_t key, hashtab_datum_t datum, void *p)
{
	policydb_t *newp;
	class_datum_t *cladatum, *cladatum2;

	newp = (policydb_t *) p;
	cladatum = (class_datum_t *) datum;

	cladatum2 =
	    (class_datum_t *) hashtab_search(newp->p_classes.table, key);
	if (!cladatum2) {
		ERR(NULL, "class %s disappeared", key);
		return -1;
	}
	if (cladatum->s.value != cladatum2->s.value) {
		ERR(NULL, "the value of class %s changed", key);
		return -1;
	}
	if ((cladatum->comdatum && !cladatum2->comdatum) ||
	    (!cladatum->comdatum && cladatum2->comdatum)) {
		ERR(NULL, "the inherits clause for the access "
		    "vector definition for class %s changed", key);
		return -1;
	}
	if (cladatum->comdatum) {
		if (hashtab_map
		    (cladatum->comdatum->permissions.table, validate_perm,
		     cladatum2->comdatum->permissions.table)) {
			ERR(NULL,
			    " in the access vector definition "
			    "for class %s\n", key);
			return -1;
		}
	}
	if (hashtab_map(cladatum->permissions.table, validate_perm,
			cladatum2->permissions.table)) {
		ERR(NULL, " in access vector definition for class %s", key);
		return -1;
	}
	return 0;
}

/* Clone the SID into the new SID table. */
static int clone_sid(sepol_security_id_t sid,
		     context_struct_t * context, void *arg)
{
	sidtab_t *s = arg;

	return sepol_sidtab_insert(s, sid, context);
}

static inline int convert_context_handle_invalid_context(context_struct_t *
							 context)
{
	if (selinux_enforcing) {
		return -EINVAL;
	} else {
		sepol_security_context_t s;
		size_t len;

		context_to_string(NULL, policydb, context, &s, &len);
		ERR(NULL, "context %s is invalid", s);
		free(s);
		return 0;
	}
}

typedef struct {
	policydb_t *oldp;
	policydb_t *newp;
} convert_context_args_t;

/*
 * Convert the values in the security context
 * structure `c' from the values specified
 * in the policy `p->oldp' to the values specified
 * in the policy `p->newp'.  Verify that the
 * context is valid under the new policy.
 */
static int convert_context(sepol_security_id_t key __attribute__ ((unused)),
			   context_struct_t * c, void *p)
{
	convert_context_args_t *args;
	context_struct_t oldc;
	role_datum_t *role;
	type_datum_t *typdatum;
	user_datum_t *usrdatum;
	sepol_security_context_t s;
	size_t len;
	int rc = -EINVAL;

	args = (convert_context_args_t *) p;

	if (context_cpy(&oldc, c))
		return -ENOMEM;

	/* Convert the user. */
	usrdatum = (user_datum_t *) hashtab_search(args->newp->p_users.table,
						   args->oldp->
						   p_user_val_to_name[c->user -
								      1]);

	if (!usrdatum) {
		goto bad;
	}
	c->user = usrdatum->s.value;

	/* Convert the role. */
	role = (role_datum_t *) hashtab_search(args->newp->p_roles.table,
					       args->oldp->
					       p_role_val_to_name[c->role - 1]);
	if (!role) {
		goto bad;
	}
	c->role = role->s.value;

	/* Convert the type. */
	typdatum = (type_datum_t *)
	    hashtab_search(args->newp->p_types.table,
			   args->oldp->p_type_val_to_name[c->type - 1]);
	if (!typdatum) {
		goto bad;
	}
	c->type = typdatum->s.value;

	rc = mls_convert_context(args->oldp, args->newp, c);
	if (rc)
		goto bad;

	/* Check the validity of the new context. */
	if (!policydb_context_isvalid(args->newp, c)) {
		rc = convert_context_handle_invalid_context(&oldc);
		if (rc)
			goto bad;
	}

	context_destroy(&oldc);
	return 0;

      bad:
	context_to_string(NULL, policydb, &oldc, &s, &len);
	context_destroy(&oldc);
	ERR(NULL, "invalidating context %s", s);
	free(s);
	return rc;
}

/* Reading from a policy "file". */
int hidden next_entry(void *buf, struct policy_file *fp, size_t bytes)
{
	size_t nread;

	switch (fp->type) {
	case PF_USE_STDIO:
		nread = fread(buf, bytes, 1, fp->fp);

		if (nread != 1)
			return -1;
		break;
	case PF_USE_MEMORY:
		if (bytes > fp->len)
			return -1;
		memcpy(buf, fp->data, bytes);
		fp->data += bytes;
		fp->len -= bytes;
		break;
	default:
		return -1;
	}
	return 0;
}

size_t hidden put_entry(const void *ptr, size_t size, size_t n,
			struct policy_file *fp)
{
	size_t bytes = size * n;

	switch (fp->type) {
	case PF_USE_STDIO:
		return fwrite(ptr, size, n, fp->fp);
	case PF_USE_MEMORY:
		if (bytes > fp->len) {
			errno = ENOSPC;
			return 0;
		}

		memcpy(fp->data, ptr, bytes);
		fp->data += bytes;
		fp->len -= bytes;
		return n;
	case PF_LEN:
		fp->len += bytes;
		return n;
	default:
		return 0;
	}
	return 0;
}

/*
 * Read a new set of configuration data from 
 * a policy database binary representation file.
 *
 * Verify that each class that is defined under the
 * existing policy is still defined with the same 
 * attributes in the new policy.  
 *
 * Convert the context structures in the SID table to the
 * new representation and verify that all entries
 * in the SID table are valid under the new policy. 
 *
 * Change the active policy database to use the new 
 * configuration data.  
 *
 * Reset the access vector cache.
 */
int hidden sepol_load_policy(void *data, size_t len)
{
	policydb_t oldpolicydb, newpolicydb;
	sidtab_t oldsidtab, newsidtab;
	convert_context_args_t args;
	int rc = 0;
	struct policy_file file, *fp;

	policy_file_init(&file);
	file.type = PF_USE_MEMORY;
	file.data = data;
	file.len = len;
	fp = &file;

	if (policydb_init(&newpolicydb))
		return -ENOMEM;

	if (policydb_read(&newpolicydb, fp, 1)) {
		return -EINVAL;
	}

	sepol_sidtab_init(&newsidtab);

	/* Verify that the existing classes did not change. */
	if (hashtab_map
	    (policydb->p_classes.table, validate_class, &newpolicydb)) {
		ERR(NULL, "the definition of an existing class changed");
		rc = -EINVAL;
		goto err;
	}

	/* Clone the SID table. */
	sepol_sidtab_shutdown(sidtab);
	if (sepol_sidtab_map(sidtab, clone_sid, &newsidtab)) {
		rc = -ENOMEM;
		goto err;
	}

	/* Convert the internal representations of contexts 
	   in the new SID table and remove invalid SIDs. */
	args.oldp = policydb;
	args.newp = &newpolicydb;
	sepol_sidtab_map_remove_on_error(&newsidtab, convert_context, &args);

	/* Save the old policydb and SID table to free later. */
	memcpy(&oldpolicydb, policydb, sizeof *policydb);
	sepol_sidtab_set(&oldsidtab, sidtab);

	/* Install the new policydb and SID table. */
	memcpy(policydb, &newpolicydb, sizeof *policydb);
	sepol_sidtab_set(sidtab, &newsidtab);

	/* Free the old policydb and SID table. */
	policydb_destroy(&oldpolicydb);
	sepol_sidtab_destroy(&oldsidtab);

	return 0;

      err:
	sepol_sidtab_destroy(&newsidtab);
	policydb_destroy(&newpolicydb);
	return rc;

}

/*
 * Return the SIDs to use for an unlabeled file system
 * that is being mounted from the device with the
 * the kdevname `name'.  The `fs_sid' SID is returned for 
 * the file system and the `file_sid' SID is returned
 * for all files within that file system.
 */
int hidden sepol_fs_sid(char *name,
			sepol_security_id_t * fs_sid,
			sepol_security_id_t * file_sid)
{
	int rc = 0;
	ocontext_t *c;

	c = policydb->ocontexts[OCON_FS];
	while (c) {
		if (strcmp(c->u.name, name) == 0)
			break;
		c = c->next;
	}

	if (c) {
		if (!c->sid[0] || !c->sid[1]) {
			rc = sepol_sidtab_context_to_sid(sidtab,
							 &c->context[0],
							 &c->sid[0]);
			if (rc)
				goto out;
			rc = sepol_sidtab_context_to_sid(sidtab,
							 &c->context[1],
							 &c->sid[1]);
			if (rc)
				goto out;
		}
		*fs_sid = c->sid[0];
		*file_sid = c->sid[1];
	} else {
		*fs_sid = SECINITSID_FS;
		*file_sid = SECINITSID_FILE;
	}

      out:
	return rc;
}

/*
 * Return the SID of the port specified by
 * `domain', `type', `protocol', and `port'.
 */
int hidden sepol_port_sid(uint16_t domain __attribute__ ((unused)),
			  uint16_t type __attribute__ ((unused)),
			  uint8_t protocol,
			  uint16_t port, sepol_security_id_t * out_sid)
{
	ocontext_t *c;
	int rc = 0;

	c = policydb->ocontexts[OCON_PORT];
	while (c) {
		if (c->u.port.protocol == protocol &&
		    c->u.port.low_port <= port && c->u.port.high_port >= port)
			break;
		c = c->next;
	}

	if (c) {
		if (!c->sid[0]) {
			rc = sepol_sidtab_context_to_sid(sidtab,
							 &c->context[0],
							 &c->sid[0]);
			if (rc)
				goto out;
		}
		*out_sid = c->sid[0];
	} else {
		*out_sid = SECINITSID_PORT;
	}

      out:
	return rc;
}

/*
 * Return the SIDs to use for a network interface
 * with the name `name'.  The `if_sid' SID is returned for 
 * the interface and the `msg_sid' SID is returned as 
 * the default SID for messages received on the
 * interface.
 */
int hidden sepol_netif_sid(char *name,
			   sepol_security_id_t * if_sid,
			   sepol_security_id_t * msg_sid)
{
	int rc = 0;
	ocontext_t *c;

	c = policydb->ocontexts[OCON_NETIF];
	while (c) {
		if (strcmp(name, c->u.name) == 0)
			break;
		c = c->next;
	}

	if (c) {
		if (!c->sid[0] || !c->sid[1]) {
			rc = sepol_sidtab_context_to_sid(sidtab,
							 &c->context[0],
							 &c->sid[0]);
			if (rc)
				goto out;
			rc = sepol_sidtab_context_to_sid(sidtab,
							 &c->context[1],
							 &c->sid[1]);
			if (rc)
				goto out;
		}
		*if_sid = c->sid[0];
		*msg_sid = c->sid[1];
	} else {
		*if_sid = SECINITSID_NETIF;
		*msg_sid = SECINITSID_NETMSG;
	}

      out:
	return rc;
}

static int match_ipv6_addrmask(uint32_t * input, uint32_t * addr,
			       uint32_t * mask)
{
	int i, fail = 0;

	for (i = 0; i < 4; i++)
		if (addr[i] != (input[i] & mask[i])) {
			fail = 1;
			break;
		}

	return !fail;
}

/*
 * Return the SID of the node specified by the address
 * `addrp' where `addrlen' is the length of the address
 * in bytes and `domain' is the communications domain or
 * address family in which the address should be interpreted.
 */
int hidden sepol_node_sid(uint16_t domain,
			  void *addrp,
			  size_t addrlen, sepol_security_id_t * out_sid)
{
	int rc = 0;
	ocontext_t *c;

	switch (domain) {
	case AF_INET:{
			uint32_t addr;

			if (addrlen != sizeof(uint32_t)) {
				rc = -EINVAL;
				goto out;
			}

			addr = *((uint32_t *) addrp);

			c = policydb->ocontexts[OCON_NODE];
			while (c) {
				if (c->u.node.addr == (addr & c->u.node.mask))
					break;
				c = c->next;
			}
			break;
		}

	case AF_INET6:
		if (addrlen != sizeof(uint64_t) * 2) {
			rc = -EINVAL;
			goto out;
		}

		c = policydb->ocontexts[OCON_NODE6];
		while (c) {
			if (match_ipv6_addrmask(addrp, c->u.node6.addr,
						c->u.node6.mask))
				break;
			c = c->next;
		}
		break;

	default:
		*out_sid = SECINITSID_NODE;
		goto out;
	}

	if (c) {
		if (!c->sid[0]) {
			rc = sepol_sidtab_context_to_sid(sidtab,
							 &c->context[0],
							 &c->sid[0]);
			if (rc)
				goto out;
		}
		*out_sid = c->sid[0];
	} else {
		*out_sid = SECINITSID_NODE;
	}

      out:
	return rc;
}

/*
 * Generate the set of SIDs for legal security contexts
 * for a given user that can be reached by `fromsid'.
 * Set `*sids' to point to a dynamically allocated 
 * array containing the set of SIDs.  Set `*nel' to the
 * number of elements in the array.
 */
#define SIDS_NEL 25

int hidden sepol_get_user_sids(sepol_security_id_t fromsid,
			       char *username,
			       sepol_security_id_t ** sids, uint32_t * nel)
{
	context_struct_t *fromcon, usercon;
	sepol_security_id_t *mysids, *mysids2, sid;
	uint32_t mynel = 0, maxnel = SIDS_NEL;
	user_datum_t *user;
	role_datum_t *role;
	struct sepol_av_decision avd;
	int rc = 0;
	unsigned int i, j, reason;
	ebitmap_node_t *rnode, *tnode;

	fromcon = sepol_sidtab_search(sidtab, fromsid);
	if (!fromcon) {
		rc = -EINVAL;
		goto out;
	}

	user = (user_datum_t *) hashtab_search(policydb->p_users.table,
					       username);
	if (!user) {
		rc = -EINVAL;
		goto out;
	}
	usercon.user = user->s.value;

	mysids = malloc(maxnel * sizeof(sepol_security_id_t));
	if (!mysids) {
		rc = -ENOMEM;
		goto out;
	}
	memset(mysids, 0, maxnel * sizeof(sepol_security_id_t));

	ebitmap_for_each_bit(&user->roles.roles, rnode, i) {
		if (!ebitmap_node_get_bit(rnode, i))
			continue;
		role = policydb->role_val_to_struct[i];
		usercon.role = i + 1;
		ebitmap_for_each_bit(&role->types.types, tnode, j) {
			if (!ebitmap_node_get_bit(tnode, j))
				continue;
			usercon.type = j + 1;
			if (usercon.type == fromcon->type)
				continue;

			if (mls_setup_user_range
			    (fromcon, user, &usercon, policydb->mls))
				continue;

			rc = context_struct_compute_av(fromcon, &usercon,
						       SECCLASS_PROCESS,
						       PROCESS__TRANSITION,
						       &avd, &reason);
			if (rc || !(avd.allowed & PROCESS__TRANSITION))
				continue;
			rc = sepol_sidtab_context_to_sid(sidtab, &usercon,
							 &sid);
			if (rc) {
				free(mysids);
				goto out;
			}
			if (mynel < maxnel) {
				mysids[mynel++] = sid;
			} else {
				maxnel += SIDS_NEL;
				mysids2 =
				    malloc(maxnel *
					   sizeof(sepol_security_id_t));

				if (!mysids2) {
					rc = -ENOMEM;
					free(mysids);
					goto out;
				}
				memset(mysids2, 0,
				       maxnel * sizeof(sepol_security_id_t));
				memcpy(mysids2, mysids,
				       mynel * sizeof(sepol_security_id_t));
				free(mysids);
				mysids = mysids2;
				mysids[mynel++] = sid;
			}
		}
	}

	*sids = mysids;
	*nel = mynel;

      out:
	return rc;
}

/*
 * Return the SID to use for a file in a filesystem
 * that cannot support a persistent label mapping or use another
 * fixed labeling behavior like transition SIDs or task SIDs.
 */
int hidden sepol_genfs_sid(const char *fstype,
			   char *path,
			   sepol_security_class_t sclass,
			   sepol_security_id_t * sid)
{
	size_t len;
	genfs_t *genfs;
	ocontext_t *c;
	int rc = 0, cmp = 0;

	for (genfs = policydb->genfs; genfs; genfs = genfs->next) {
		cmp = strcmp(fstype, genfs->fstype);
		if (cmp <= 0)
			break;
	}

	if (!genfs || cmp) {
		*sid = SECINITSID_UNLABELED;
		rc = -ENOENT;
		goto out;
	}

	for (c = genfs->head; c; c = c->next) {
		len = strlen(c->u.name);
		if ((!c->v.sclass || sclass == c->v.sclass) &&
		    (strncmp(c->u.name, path, len) == 0))
			break;
	}

	if (!c) {
		*sid = SECINITSID_UNLABELED;
		rc = -ENOENT;
		goto out;
	}

	if (!c->sid[0]) {
		rc = sepol_sidtab_context_to_sid(sidtab,
						 &c->context[0], &c->sid[0]);
		if (rc)
			goto out;
	}

	*sid = c->sid[0];
      out:
	return rc;
}

int hidden sepol_fs_use(const char *fstype,
			unsigned int *behavior, sepol_security_id_t * sid)
{
	int rc = 0;
	ocontext_t *c;

	c = policydb->ocontexts[OCON_FSUSE];
	while (c) {
		if (strcmp(fstype, c->u.name) == 0)
			break;
		c = c->next;
	}

	if (c) {
		*behavior = c->v.behavior;
		if (!c->sid[0]) {
			rc = sepol_sidtab_context_to_sid(sidtab,
							 &c->context[0],
							 &c->sid[0]);
			if (rc)
				goto out;
		}
		*sid = c->sid[0];
	} else {
		rc = sepol_genfs_sid(fstype, "/", SECCLASS_DIR, sid);
		if (rc) {
			*behavior = SECURITY_FS_USE_NONE;
			rc = 0;
		} else {
			*behavior = SECURITY_FS_USE_GENFS;
		}
	}

      out:
	return rc;
}

/* FLASK */
