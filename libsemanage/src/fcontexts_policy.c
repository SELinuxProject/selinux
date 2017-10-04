/* Copyright (C) 2005 Red Hat, Inc. */

struct semanage_fcontext;
struct semanage_fcontext_key;
typedef struct semanage_fcontext_key record_key_t;
typedef struct semanage_fcontext record_t;
#define DBASE_RECORD_DEFINED

#include "fcontext_internal.h"
#include "handle.h"
#include "database.h"

int semanage_fcontext_query(semanage_handle_t * handle,
			    const semanage_fcontext_key_t * key,
			    semanage_fcontext_t ** response)
{

	dbase_config_t *dconfig = semanage_fcontext_dbase_policy(handle);
	return dbase_query(handle, dconfig, key, response);
}

int semanage_fcontext_exists(semanage_handle_t * handle,
			     const semanage_fcontext_key_t * key, int *response)
{

	dbase_config_t *dconfig = semanage_fcontext_dbase_policy(handle);
	return dbase_exists(handle, dconfig, key, response);
}

int semanage_fcontext_count(semanage_handle_t * handle, unsigned int *response)
{

	dbase_config_t *dconfig = semanage_fcontext_dbase_policy(handle);
	return dbase_count(handle, dconfig, response);
}

int semanage_fcontext_iterate(semanage_handle_t * handle,
			      int (*handler) (const semanage_fcontext_t *
					      record, void *varg),
			      void *handler_arg)
{

	dbase_config_t *dconfig = semanage_fcontext_dbase_policy(handle);
	return dbase_iterate(handle, dconfig, handler, handler_arg);
}

int semanage_fcontext_list(semanage_handle_t * handle,
			   semanage_fcontext_t *** records, unsigned int *count)
{

	dbase_config_t *dconfig = semanage_fcontext_dbase_policy(handle);
	return dbase_list(handle, dconfig, records, count);
}

int semanage_fcontext_list_homedirs(semanage_handle_t * handle,
			   semanage_fcontext_t *** records, unsigned int *count)
{

	dbase_config_t *dconfig = semanage_fcontext_dbase_homedirs(handle);
	return dbase_list(handle, dconfig, records, count);
}
