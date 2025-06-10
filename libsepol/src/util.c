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
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <sepol/policydb/flask_types.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/util.h>

#include "private.h"

struct val_to_name {
	unsigned int val;
	const char *name;
};

/* Add an unsigned integer to a dynamically reallocated array.  *cnt
 * is a reference pointer to the number of values already within array
 * *a; it will be incremented upon successfully appending i.  If *a is
 * NULL then this function will create a new array (*cnt is reset to
 * 0).  Return 0 on success, -1 on out of memory. */
int add_i_to_a(uint32_t i, uint32_t * cnt, uint32_t ** a)
{
	uint32_t *new;

	if (cnt == NULL || *cnt == UINT32_MAX || a == NULL)
		return -1;

	/* FIX ME: This is not very elegant! We use an array that we
	 * grow as new uint32_t are added to an array.  But rather
	 * than be smart about it, for now we realloc() the array each
	 * time a new uint32_t is added! */
	if (*a != NULL)
		new = (uint32_t *) reallocarray(*a, *cnt + 1, sizeof(uint32_t));
	else {			/* empty list */

		*cnt = 0;
		new = (uint32_t *) malloc(sizeof(uint32_t));
	}
	if (new == NULL) {
		return -1;
	}
	new[*cnt] = i;
	(*cnt)++;
	*a = new;
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

char *sepol_av_to_string(const policydb_t *policydbp, sepol_security_class_t tclass,
			 sepol_access_vector_t av)
{
	struct val_to_name v;
	const class_datum_t *cladatum = policydbp->class_val_to_struct[tclass - 1];
	uint32_t i;
	int rc;
	char *buffer = NULL, *p;
	int len;
	size_t remaining, size = 64;

retry:
	if (__builtin_mul_overflow(size, 2, &size))
		goto err;
	p = realloc(buffer, size);
	if (!p)
		goto err;
	*p = '\0'; /* Just in case there are no permissions */
	buffer = p;
	remaining = size;

	for (i = 0; i < cladatum->permissions.nprim; i++) {
		if (av & (UINT32_C(1) << i)) {
			v.val = i + 1;
			rc = hashtab_map(cladatum->permissions.table,
					 perm_name, &v);
			if (!rc && cladatum->comdatum) {
				rc = hashtab_map(cladatum->comdatum->
						 permissions.table, perm_name,
						 &v);
			}
			if (rc == 1) {
				len = snprintf(p, remaining, " %s", v.name);
				if (len < 0)
					goto err;
				if ((size_t) len >= remaining)
					goto retry;
				p += len;
				remaining -= len;
			}
		}
	}

	return buffer;

err:
	free(buffer);
	return NULL;
}

#define next_bit_in_range(i, p) (((i) + 1 < sizeof(p)*8) && xperm_test(((i) + 1), p))

char *sepol_extended_perms_to_string(const avtab_extended_perms_t *xperms)
{
	uint16_t value;
	uint16_t low_bit;
	uint16_t low_value;
	unsigned int bit;
	unsigned int in_range;
	char *buffer = NULL, *p;
	int len;
	size_t remaining, size = 128;

	if ((xperms->specified != AVTAB_XPERMS_IOCTLFUNCTION)
		&& (xperms->specified != AVTAB_XPERMS_IOCTLDRIVER)
		&& (xperms->specified != AVTAB_XPERMS_NLMSG))
		return NULL;

retry:
	if (__builtin_mul_overflow(size, 2, &size))
		goto err;
	p = realloc(buffer, size);
	if (!p)
		goto err;
	buffer = p;
	remaining = size;

	if ((xperms->specified == AVTAB_XPERMS_IOCTLFUNCTION)
		|| (xperms->specified == AVTAB_XPERMS_IOCTLDRIVER)) {
		len = snprintf(p, remaining, "ioctl { ");
	} else {
		len = snprintf(p, remaining, "nlmsg { ");
	}
	if (len < 0 || (size_t)len >= remaining)
		goto err;
	p += len;
	remaining -= len;

	in_range = 0;
	for (bit = 0; bit < sizeof(xperms->perms)*8; bit++) {
		if (!xperm_test(bit, xperms->perms))
			continue;

		if (in_range && next_bit_in_range(bit, xperms->perms)) {
			/* continue until high value found */
			continue;
		} else if (next_bit_in_range(bit, xperms->perms)) {
			/* low value */
			low_bit = bit;
			in_range = 1;
			continue;
		}

		if (xperms->specified == AVTAB_XPERMS_IOCTLFUNCTION || xperms->specified == AVTAB_XPERMS_NLMSG) {
			value = xperms->driver<<8 | bit;
			if (in_range) {
				low_value = xperms->driver<<8 | low_bit;
				len = snprintf(p, remaining, "0x%hx-0x%hx ", low_value, value);
			} else {
				len = snprintf(p, remaining, "0x%hx ", value);
			}
		} else if (xperms->specified == AVTAB_XPERMS_IOCTLDRIVER) {
			value = bit << 8;
			if (in_range) {
				low_value = low_bit << 8;
				len = snprintf(p, remaining, "0x%hx-0x%hx ", low_value, (uint16_t) (value|0xff));
			} else {
				len = snprintf(p, remaining, "0x%hx-0x%hx ", value, (uint16_t) (value|0xff));
			}

		}

		if (len < 0)
			goto err;
		if ((size_t) len >= remaining)
			goto retry;

		p += len;
		remaining -= len;
		if (in_range)
			in_range = 0;
	}

	len = snprintf(p, remaining, "}");
	if (len < 0)
		goto err;
	if ((size_t) len >= remaining)
		goto retry;

	return buffer;

err:
	free(buffer);
	return NULL;
}

/*
 * The tokenize and tokenize_str functions may be used to
 * replace sscanf to read tokens from buffers.
 */

/* Read a token from a buffer */
static inline int tokenize_str(char delim, char **str, const char **ptr, size_t *len)
{
	const char *tmp_buf = *ptr;
	*str = NULL;

	while (**ptr != '\0') {
		if (isspace(delim) && isspace(**ptr)) {
			(*ptr)++;
			break;
		} else if (!isspace(delim) && **ptr == delim) {
			(*ptr)++;
			break;
		}

		(*ptr)++;
	}

	*len = *ptr - tmp_buf;
	/* If the end of the string has not been reached, this will ensure the
	 * delimiter is not included when returning the token.
	 */
	if (**ptr != '\0') {
		(*len)--;
	}

	*str = strndup(tmp_buf, *len);
	if (!*str) {
		return -1;
	}

	/* Squash spaces if the delimiter is a whitespace character */
	while (**ptr != '\0' && isspace(delim) && isspace(**ptr)) {
		(*ptr)++;
	}

	return 0;
}

/*
 * line_buf - Buffer containing string to tokenize.
 * delim - The delimiter used to tokenize line_buf. A whitespace delimiter will
 *	    be tokenized using isspace().
 * num_args - The number of parameter entries to process.
 * ...      - A 'char **' for each parameter.
 * returns  - The number of items processed.
 *
 * This function calls tokenize_str() to do the actual string processing. The
 * caller is responsible for calling free() on each additional argument. The
 * function will not tokenize more than num_args and the last argument will
 * contain the remaining content of line_buf. If the delimiter is any whitespace
 * character, then all whitespace will be squashed.
 */
int tokenize(const char *line_buf, char delim, int num_args, ...)
{
	char **arg;
	const char *buf_p;
	int rc, items;
	size_t arg_len = 0;
	va_list ap;

	buf_p = line_buf;

	/* Process the arguments */
	va_start(ap, num_args);

	for (items = 0; items < num_args && *buf_p != '\0'; items++) {
		arg = va_arg(ap, char **);

		/* Save the remainder of the string in arg */
		if (items == num_args - 1) {
			*arg = strdup(buf_p);
			if (*arg == NULL) {
				goto exit;
			}

			continue;
		}

		rc = tokenize_str(delim, arg, &buf_p, &arg_len);
		if (rc < 0) {
			goto exit;
		}
	}

exit:
	va_end(ap);
	return items;
}
