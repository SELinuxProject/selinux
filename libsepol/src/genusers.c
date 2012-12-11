#include <stdio.h>

#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>

#include <sepol/policydb/policydb.h>

#ifndef DARWIN
#include <stdio_ext.h>
#endif

#include <stdarg.h>

#include "debug.h"
#include "private.h"
#include "dso.h"
#include "mls.h"

/* -- Deprecated -- */

void sepol_set_delusers(int on __attribute((unused)))
{
	WARN(NULL, "Deprecated interface");
}

#undef BADLINE
#define BADLINE() { \
	ERR(NULL, "invalid entry %s (%s:%u)", \
		buffer, path, lineno); \
	continue; \
}

static int load_users(struct policydb *policydb, const char *path)
{
	FILE *fp;
	char *buffer = NULL, *p, *q, oldc;
	size_t len = 0;
	ssize_t nread;
	unsigned lineno = 0, islist = 0, bit;
	user_datum_t *usrdatum;
	role_datum_t *roldatum;
	ebitmap_node_t *rnode;

	fp = fopen(path, "r");
	if (fp == NULL)
		return -1;

#ifdef DARWIN
	if ((buffer = (char *)malloc(255 * sizeof(char))) == NULL) {
	  ERR(NULL, "out of memory");
	  return -1;
	}

	while(fgets(buffer, 255, fp) != NULL) {
#else
	__fsetlocking(fp, FSETLOCKING_BYCALLER);
	while ((nread = getline(&buffer, &len, fp)) > 0) {
#endif

		lineno++;
		if (buffer[nread - 1] == '\n')
			buffer[nread - 1] = 0;
		p = buffer;
		while (*p && isspace(*p))
			p++;
		if (!(*p) || *p == '#')
			continue;

		if (strncasecmp(p, "user", 4))
			BADLINE();
		p += 4;
		if (!isspace(*p))
			BADLINE();
		while (*p && isspace(*p))
			p++;
		if (!(*p))
			BADLINE();
		q = p;
		while (*p && !isspace(*p))
			p++;
		if (!(*p))
			BADLINE();
		*p++ = 0;

		usrdatum = hashtab_search(policydb->p_users.table, q);
		if (usrdatum) {
			/* Replacing an existing user definition. */
			ebitmap_destroy(&usrdatum->roles.roles);
			ebitmap_init(&usrdatum->roles.roles);
		} else {
			char *id = strdup(q);

			if (!id) {
				ERR(NULL, "out of memory");
				free(buffer);
				fclose(fp);
				return -1;
			}

			/* Adding a new user definition. */
			usrdatum = malloc(sizeof(user_datum_t));
			if (!usrdatum) {
				ERR(NULL, "out of memory");
				free(buffer);
				free(id);
				fclose(fp);
				return -1;
			}

			user_datum_init(usrdatum);
			usrdatum->s.value = ++policydb->p_users.nprim;
			if (hashtab_insert(policydb->p_users.table,
					   id, (hashtab_datum_t) usrdatum)) {
				ERR(NULL, "out of memory");
				free(buffer);
				free(id);
				user_datum_destroy(usrdatum);
				free(usrdatum);
				fclose(fp);
				return -1;
			}
		}

		while (*p && isspace(*p))
			p++;
		if (!(*p))
			BADLINE();
		if (strncasecmp(p, "roles", 5))
			BADLINE();
		p += 5;
		if (!isspace(*p))
			BADLINE();
		while (*p && isspace(*p))
			p++;
		if (!(*p))
			BADLINE();
		if (*p == '{') {
			islist = 1;
			p++;
		} else
			islist = 0;

		oldc = 0;
		do {
			while (*p && isspace(*p))
				p++;
			if (!(*p))
				break;

			q = p;
			while (*p && *p != ';' && *p != '}' && !isspace(*p))
				p++;
			if (!(*p))
				break;
			if (*p == '}')
				islist = 0;
			oldc = *p;
			*p++ = 0;
			if (!q[0])
				break;

			roldatum = hashtab_search(policydb->p_roles.table, q);
			if (!roldatum) {
				ERR(NULL, "undefined role %s (%s:%u)",
				    q, path, lineno);
				continue;
			}
			/* Set the role and every role it dominates */
			ebitmap_for_each_bit(&roldatum->dominates, rnode, bit) {
				if (ebitmap_node_get_bit(rnode, bit))
					if (ebitmap_set_bit
					    (&usrdatum->roles.roles, bit, 1)) {
						ERR(NULL, "out of memory");
						free(buffer);
						fclose(fp);
						return -1;
					}
			}
		} while (islist);
		if (oldc == 0)
			BADLINE();

		if (policydb->mls) {
			context_struct_t context;
			char *scontext, *r, *s;

			while (*p && isspace(*p))
				p++;
			if (!(*p))
				BADLINE();
			if (strncasecmp(p, "level", 5))
				BADLINE();
			p += 5;
			if (!isspace(*p))
				BADLINE();
			while (*p && isspace(*p))
				p++;
			if (!(*p))
				BADLINE();
			q = p;
			while (*p && strncasecmp(p, "range", 5))
				p++;
			if (!(*p))
				BADLINE();
			*--p = 0;
			p++;

			scontext = malloc(p - q);
			if (!scontext) {
				ERR(NULL, "out of memory");
				free(buffer);
				fclose(fp);
				return -1;
			}
			r = scontext;
			s = q;
			while (*s) {
				if (!isspace(*s))
					*r++ = *s;
				s++;
			}
			*r = 0;
			r = scontext;

			context_init(&context);
			if (mls_context_to_sid(policydb, oldc, &r, &context) <
			    0) {
				ERR(NULL, "invalid level %s (%s:%u)", scontext,
				    path, lineno);
				free(scontext);
				continue;

			}
			free(scontext);
			memcpy(&usrdatum->dfltlevel, &context.range.level[0],
			       sizeof(usrdatum->dfltlevel));

			if (strncasecmp(p, "range", 5))
				BADLINE();
			p += 5;
			if (!isspace(*p))
				BADLINE();
			while (*p && isspace(*p))
				p++;
			if (!(*p))
				BADLINE();
			q = p;
			while (*p && *p != ';')
				p++;
			if (!(*p))
				BADLINE();
			*p++ = 0;

			scontext = malloc(p - q);
			if (!scontext) {
				ERR(NULL, "out of memory");
				free(buffer);
				fclose(fp);
				return -1;
			}
			r = scontext;
			s = q;
			while (*s) {
				if (!isspace(*s))
					*r++ = *s;
				s++;
			}
			*r = 0;
			r = scontext;

			context_init(&context);
			if (mls_context_to_sid(policydb, oldc, &r, &context) <
			    0) {
				ERR(NULL, "invalid range %s (%s:%u)", scontext,
				    path, lineno);
				free(scontext);
				continue;
			}
			free(scontext);
			memcpy(&usrdatum->range, &context.range,
			       sizeof(usrdatum->range));
		}
	}

	free(buffer);
	fclose(fp);
	return 0;
}

int sepol_genusers(void *data, size_t len,
		   const char *usersdir, void **newdata, size_t * newlen)
{
	struct policydb policydb;
	char path[PATH_MAX];

	/* Construct policy database */
	if (policydb_init(&policydb))
		goto err;
	if (policydb_from_image(NULL, data, len, &policydb) < 0)
		goto err;

	/* Load locally defined users. */
	snprintf(path, sizeof path, "%s/local.users", usersdir);
	if (load_users(&policydb, path) < 0)
		goto err_destroy;

	/* Write policy database */
	if (policydb_to_image(NULL, &policydb, newdata, newlen) < 0)
		goto err_destroy;

	policydb_destroy(&policydb);
	return 0;

      err_destroy:
	policydb_destroy(&policydb);

      err:
	return -1;
}

int hidden sepol_genusers_policydb(policydb_t * policydb, const char *usersdir)
{
	char path[PATH_MAX];

	/* Load locally defined users. */
	snprintf(path, sizeof path, "%s/local.users", usersdir);
	if (load_users(policydb, path) < 0) {
		ERR(NULL, "unable to load local.users: %s", strerror(errno));
		return -1;
	}

	if (policydb_reindex_users(policydb) < 0) {
		ERR(NULL, "unable to reindex users: %s", strerror(errno));
		return -1;

	}

	return 0;
}

/* -- End Deprecated -- */
