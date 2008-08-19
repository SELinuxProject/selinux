/*
 * Generalized labeling frontend for userspace object managers.
 *
 * Author : Eamon Walsh <ewalsh@epoch.ncsc.mil>
 */

#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "callbacks.h"
#include "label_internal.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

typedef int (*selabel_initfunc)(struct selabel_handle *rec,
				struct selinux_opt *opts, unsigned nopts);

static selabel_initfunc initfuncs[] = {
	&selabel_file_init,
	&selabel_media_init,
	&selabel_x_init
};

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
	struct selabel_lookup_rec *lr = rec->func_lookup(rec, key, type);
	if (!lr)
		return NULL;

	if (compat_validate(rec, lr, "file_contexts", 0))
		return NULL;

	if (translating && !lr->ctx_trans &&
	    selinux_raw_to_trans_context(lr->ctx_raw, &lr->ctx_trans))
		return NULL;

	return lr;
}

int selabel_lookup(struct selabel_handle *rec, security_context_t *con,
		   const char *key, int type)
{
	struct selabel_lookup_rec *lr;

	lr = selabel_lookup_common(rec, 1, key, type);
	if (!lr)
		return -1;

	*con = strdup(lr->ctx_trans);
	return *con ? 0 : -1;
}

int selabel_lookup_raw(struct selabel_handle *rec, security_context_t *con,
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
	rec->func_close(rec);
	free(rec);
}

void selabel_stats(struct selabel_handle *rec)
{
	rec->func_stats(rec);
}
