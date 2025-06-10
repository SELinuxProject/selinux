#include <stdio.h>
#include "mls_level.h"
#include <sepol/policydb/ebitmap.h>

mls_level_t *mls_level_from_string(char *mls_context)
{
	char delim;
	char *scontextp, *p, *lptr;
	mls_level_t *l;

	if (!mls_context) {
		return NULL;
	}

	l = (mls_level_t *) calloc(1, sizeof(mls_level_t));
	if (!l)
		return NULL;

	/* Extract low sensitivity. */
	scontextp = p = mls_context;
	while (*p && *p != ':' && *p != '-')
		p++;

	delim = *p;
	if (delim != 0)
		*p++ = 0;

	if (*scontextp != 's')
		goto err;
	l->sens = atoi(scontextp + 1);

	if (delim == ':') {
		/* Extract category set. */
		while (1) {
			scontextp = p;
			while (*p && *p != ',' && *p != '-')
				p++;
			delim = *p;
			if (delim != 0)
				*p++ = 0;

			/* Separate into level if exists */
			if ((lptr = strchr(scontextp, '.')) != NULL) {
				/* Remove '.' */
				*lptr++ = 0;
			}

			if (*scontextp != 'c')
				goto err;
			int bit = atoi(scontextp + 1);
			if (ebitmap_set_bit(&l->cat, bit, 1))
				goto err;

			/* If level, set all categories in level */
			if (lptr) {
				if (*lptr != 'c')
					goto err;
				int ubit = atoi(lptr + 1);
				int i;
				for (i = bit + 1; i <= ubit; i++) {
					if (ebitmap_set_bit
					    (&l->cat, i, 1))
						goto err;
				}
			}

			if (delim != ',')
				break;
		}
	}

	return l;

      err:
	free(l);
	return NULL;
}

/*
 * Return the length in bytes for the MLS fields of the
 * security context string representation of `context'.
 */
unsigned int mls_compute_string_len(mls_level_t *l)
{
	unsigned int len = 0;
	char temp[16];
	unsigned int i, level = 0;
	ebitmap_node_t *cnode;

	if (!l)
		return 0;

	len += snprintf(temp, sizeof(temp), "s%d", l->sens);

	ebitmap_for_each_bit(&l->cat, cnode, i) {
		if (ebitmap_node_get_bit(cnode, i)) {
			if (level) {
				level++;
				continue;
			}

			len++; /* : or ,` */

			len += snprintf(temp, sizeof(temp), "c%d", i);
			level++;
		} else {
			if (level > 1)
				len += snprintf(temp, sizeof(temp), ".c%d", i-1);
			level = 0;
		}
	}

	/* Handle case where last category is the end of level */
	if (level > 1)
		len += snprintf(temp, sizeof(temp), ".c%d", i-1);
	return len;
}

char *mls_level_to_string(mls_level_t *l)
{
	unsigned int wrote_sep, len = mls_compute_string_len(l);
	unsigned int i, level = 0;
	ebitmap_node_t *cnode;
	wrote_sep = 0;

	if (len == 0)
		return NULL;
	char *result = (char *)malloc(len + 1);
	if (!result)
		return NULL;

	char *p = result;

	p += sprintf(p, "s%d", l->sens);

	/* categories */
	ebitmap_for_each_bit(&l->cat, cnode, i) {
		if (ebitmap_node_get_bit(cnode, i)) {
			if (level) {
				level++;
				continue;
			}

			if (!wrote_sep) {
				*p++ = ':';
				wrote_sep = 1;
			} else
				*p++ = ',';
			p += sprintf(p, "c%d", i);
			level++;
		} else {
			if (level > 1) {
				if (level > 2)
					*p++ = '.';
				else
					*p++ = ',';

				p += sprintf(p, "c%d", i-1);
			}
			level = 0;
		}
	}
	/* Handle case where last category is the end of level */
	if (level > 1) {
		if (level > 2)
			*p++ = '.';
		else
			*p++ = ',';

		p += sprintf(p, "c%d", i-1);
	}

	*(result + len) = 0;
	return result;
}
