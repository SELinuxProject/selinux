/* Copyright (C) 2005 Red Hat, Inc. */

struct semanage_fcontext;
struct semanage_fcontext_key;
typedef struct semanage_fcontext_key record_key_t;
typedef struct semanage_fcontext record_t;
#define DBASE_RECORD_DEFINED

#include <stdlib.h>
#include <sepol/policydb.h>
#include <sepol/context.h>
#include "fcontext_internal.h"
#include "debug.h"
#include "handle.h"
#include "database.h"

int semanage_fcontext_modify_local(semanage_handle_t * handle,
				   const semanage_fcontext_key_t * key,
				   const semanage_fcontext_t * data)
{

	dbase_config_t *dconfig = semanage_fcontext_dbase_local(handle);
	return dbase_modify(handle, dconfig, key, data);
}

int semanage_fcontext_del_local(semanage_handle_t * handle,
				const semanage_fcontext_key_t * key)
{

	dbase_config_t *dconfig = semanage_fcontext_dbase_local(handle);
	return dbase_del(handle, dconfig, key);
}

int semanage_fcontext_query_local(semanage_handle_t * handle,
				  const semanage_fcontext_key_t * key,
				  semanage_fcontext_t ** response)
{

	dbase_config_t *dconfig = semanage_fcontext_dbase_local(handle);
	return dbase_query(handle, dconfig, key, response);
}

int semanage_fcontext_exists_local(semanage_handle_t * handle,
				   const semanage_fcontext_key_t * key,
				   int *response)
{

	dbase_config_t *dconfig = semanage_fcontext_dbase_local(handle);
	return dbase_exists(handle, dconfig, key, response);
}

int semanage_fcontext_count_local(semanage_handle_t * handle,
				  unsigned int *response)
{

	dbase_config_t *dconfig = semanage_fcontext_dbase_local(handle);
	return dbase_count(handle, dconfig, response);
}

int semanage_fcontext_iterate_local(semanage_handle_t * handle,
				    int (*handler) (const semanage_fcontext_t *
						    record, void *varg),
				    void *handler_arg)
{

	dbase_config_t *dconfig = semanage_fcontext_dbase_local(handle);
	return dbase_iterate(handle, dconfig, handler, handler_arg);
}


int semanage_fcontext_list_local(semanage_handle_t * handle,
				 semanage_fcontext_t *** records,
				 unsigned int *count)
{

	dbase_config_t *dconfig = semanage_fcontext_dbase_local(handle);
	return dbase_list(handle, dconfig, records, count);
}

struct validate_handler_arg {
	semanage_handle_t *handle;
	const sepol_policydb_t *policydb;
};

static int validate_handler(const semanage_fcontext_t * fcon, void *varg)
{

	char *str;

	/* Unpack varg */
	struct validate_handler_arg *arg = (struct validate_handler_arg *)varg;
	semanage_handle_t *handle = arg->handle;
	const sepol_policydb_t *policydb = arg->policydb;

	/* Unpack fcontext */
	const char *expr = semanage_fcontext_get_expr(fcon);
	int type = semanage_fcontext_get_type(fcon);
	const char *type_str = semanage_fcontext_get_type_str(type);
	semanage_context_t *con = semanage_fcontext_get_con(fcon);

	if (con
	    && sepol_context_check(handle->sepolh, policydb,
				   (sepol_context_t *) con) < 0)
		goto invalid;

	return 0;

      invalid:
	if (semanage_context_to_string(handle, con, &str) >= 0) {
		ERR(handle, "invalid context %s specified for %s [%s]",
		    str, expr, type_str);
		free(str);
	} else
		ERR(handle, "invalid context specified for %s [%s]",
		    expr, type_str);
	return -1;
}

int semanage_fcontext_validate_local(semanage_handle_t * handle,
					    const sepol_policydb_t * policydb)
{

	struct validate_handler_arg arg;
	arg.handle = handle;
	arg.policydb = policydb;
	return semanage_fcontext_iterate_local(handle, validate_handler, &arg);
}
