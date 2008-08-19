/* Authors: Joshua Brindle <jbrindle@tresys.com>
 * 	    Jason Tang <jtang@tresys.com>
 *
 * Copyright (C) 2005-2006 Tresys Technology, LLC
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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <sepol/policydb/flask_types.h>
#include <sepol/policydb/policydb.h>

struct val_to_name {
	unsigned int val;
	char *name;
};

/* Add an unsigned integer to a dynamically reallocated array.  *cnt
 * is a reference pointer to the number of values already within array
 * *a; it will be incremented upon successfully appending i.  If *a is
 * NULL then this function will create a new array (*cnt is reset to
 * 0).  Return 0 on success, -1 on out of memory. */
int add_i_to_a(uint32_t i, uint32_t * cnt, uint32_t ** a)
{
	if (cnt == NULL || a == NULL)
		return -1;

	/* FIX ME: This is not very elegant! We use an array that we
	 * grow as new uint32_t are added to an array.  But rather
	 * than be smart about it, for now we realloc() the array each
	 * time a new uint32_t is added! */
	if (*a != NULL)
		*a = (uint32_t *) realloc(*a, (*cnt + 1) * sizeof(uint32_t));
	else {			/* empty list */

		*cnt = 0;
		*a = (uint32_t *) malloc(sizeof(uint32_t));
	}
	if (*a == NULL) {
		return -1;
	}
	(*a)[*cnt] = i;
	(*cnt)++;
	return 0;
}

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

char *sepol_av_to_string(policydb_t * policydbp, uint32_t tclass,
			 sepol_access_vector_t av)
{
	struct val_to_name v;
	static char avbuf[1024];
	class_datum_t *cladatum;
	char *perm = NULL, *p;
	unsigned int i;
	int rc;
	int avlen = 0, len;

	cladatum = policydbp->class_val_to_struct[tclass - 1];
	p = avbuf;
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
				len =
				    snprintf(p, sizeof(avbuf) - avlen, " %s",
					     perm);
				if (len < 0
				    || (size_t) len >= (sizeof(avbuf) - avlen))
					return NULL;
				p += len;
				avlen += len;
			}
		}
	}

	return avbuf;
}
