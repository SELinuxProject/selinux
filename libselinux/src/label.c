/*
 * Generalized labeling frontend for userspace object managers.
 *
 * Author : Eamon Walsh <ewalsh@epoch.ncsc.mil>
 */

#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <selinux/selinux.h>
#include "callbacks.h"
#include "label_internal.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

typedef int (*selabel_initfunc)(struct selabel_handle *rec,
				struct selinux_opt *opts, unsigned nopts);

static selabel_initfunc initfuncs[] = {
	&selabel_file_init,
	&selabel_media_init,
	&selabel_x_init,
	&selabel_db_init,
	&selabel_property_init,
};

static void selabel_subs_fini(struct selabel_sub *ptr)
{
	struct selabel_sub *next;

	while (ptr) {
		next = ptr->next;
		free(ptr->src);
		free(ptr->dst);
		free(ptr);
		ptr = next;
	}
}

static char *selabel_sub(struct selabel_sub *ptr, const char *src)
{
	char *dst = NULL;
	int len;

	while (ptr) {
		if (strncmp(src, ptr->src, ptr->slen) == 0 ) {
			if (src[ptr->slen] == '/' || 
			    src[ptr->slen] == 0) {
				if ((src[ptr->slen] == '/') &&
				    (strcmp(ptr->dst, "/") == 0))
					len = ptr->slen + 1;
				else
					len = ptr->slen;
				if (asprintf(&dst, "%s%s", ptr->dst, &src[len]) < 0)
					return NULL;
				return dst;
			}
		}
		ptr = ptr->next;
	}
	return NULL;
}

struct selabel_sub *selabel_subs_init(const char *path, struct selabel_sub *list)
{
	char buf[1024];
	FILE *cfg = fopen(path, "r");
	struct selabel_sub *sub;

	if (!cfg)
		return list;

	while (fgets_unlocked(buf, sizeof(buf) - 1, cfg)) {
		char *ptr = NULL;
		char *src = buf;
		char *dst = NULL;

		while (*src && isspace(*src))
			src++;
		if (src[0] == '#') continue;
		ptr = src;
		while (*ptr && ! isspace(*ptr))
			ptr++;
		*ptr++ = '\0';
		if (! *src) continue;

		dst = ptr;
		while (*dst && isspace(*dst))
			dst++;
		ptr=dst;
		while (*ptr && ! isspace(*ptr))
			ptr++;
		*ptr='\0';
		if (! *dst)
			continue;

		sub = malloc(sizeof(*sub));
		if (! sub)
			goto err;
		memset(sub, 0, sizeof(*sub));

		sub->src=strdup(src);
		if (! sub->src)
			goto err;

		sub->dst=strdup(dst);
		if (! sub->dst)
			goto err;

		sub->slen = strlen(src);
		sub->next = list;
		list = sub;
	}
out:
	fclose(cfg);
	return list;
err:
	if (sub)
		free(sub->src);
	free(sub);
	goto out;
}

/*
 * Validation functions
 */

static inline int selabel_is_validate_set(struct selinux_opt *opts, unsigned n)
{
	while (n--)
		if (opts[n].type == SELABEL_OPT_VALIDATE)
			return !!opts[n].value;

	return 0;
}

int selabel_validate(struct selabel_handle *rec,
		     struct selabel_lookup_rec *contexts)
{
	int rc = 0;

	if (!rec->validating || contexts->validated)
		goto out;

	rc = selinux_validate(&contexts->ctx_raw);
	if (rc < 0)
		goto out;

	contexts->validated = 1;
out:
	return rc;
}

/*
 * Public API
 */

struct selabel_handle *selabel_open(unsigned int backend,
				    struct selinux_opt *opts, unsigned nopts)
{
	struct selabel_handle *rec = NULL;

	if (backend >= ARRAY_SIZE(initfuncs)) {
		errno = EINVAL;
		goto out;
	}

	rec = (struct selabel_handle *)malloc(sizeof(*rec));
	if (!rec)
		goto out;

	memset(rec, 0, sizeof(*rec));
	rec->backend = backend;
	rec->validating = selabel_is_validate_set(opts, nopts);

	rec->subs = NULL;
	rec->dist_subs = NULL;

	if ((*initfuncs[backend])(rec, opts, nopts)) {
		free(rec);
		rec = NULL;
	}

out:
	return rec;
}

static struct selabel_lookup_rec *
selabel_lookup_common(struct selabel_handle *rec, int translating,
		      const char *key, int type)
{
	struct selabel_lookup_rec *lr;
	char *ptr = NULL;
	char *dptr = NULL;

	if (key == NULL) {
		errno = EINVAL;
		return NULL;
	}

	ptr = selabel_sub(rec->subs, key);
	if (ptr) {
		dptr = selabel_sub(rec->dist_subs, ptr);
		if (dptr) {
			free(ptr);
			ptr = dptr;
		}
	} else {
		ptr = selabel_sub(rec->dist_subs, key);
	}
	if (ptr) {
		lr = rec->func_lookup(rec, ptr, type); 
		free(ptr);
	} else {
		lr = rec->func_lookup(rec, key, type); 
	}
	if (!lr)
		return NULL;

	if (compat_validate(rec, lr, rec->spec_file, 0))
		return NULL;

	if (translating && !lr->ctx_trans &&
	    selinux_raw_to_trans_context(lr->ctx_raw, &lr->ctx_trans))
		return NULL;

	return lr;
}

int selabel_lookup(struct selabel_handle *rec, char **con,
		   const char *key, int type)
{
	struct selabel_lookup_rec *lr;

	lr = selabel_lookup_common(rec, 1, key, type);
	if (!lr)
		return -1;

	*con = strdup(lr->ctx_trans);
	return *con ? 0 : -1;
}

int selabel_lookup_raw(struct selabel_handle *rec, char **con,
		       const char *key, int type)
{
	struct selabel_lookup_rec *lr;

	lr = selabel_lookup_common(rec, 0, key, type);
	if (!lr)
		return -1;

	*con = strdup(lr->ctx_raw);
	return *con ? 0 : -1;
}

void selabel_close(struct selabel_handle *rec)
{
	selabel_subs_fini(rec->subs);
	selabel_subs_fini(rec->dist_subs);
	rec->func_close(rec);
	free(rec->spec_file);
	free(rec);
}

void selabel_stats(struct selabel_handle *rec)
{
	rec->func_stats(rec);
}
