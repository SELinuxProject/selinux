/* Copyright (C) 2005 Red Hat, Inc. */

struct semanage_seuser;
struct semanage_seuser_key;
typedef struct semanage_seuser_key record_key_t;
typedef struct semanage_seuser record_t;
#define DBASE_RECORD_DEFINED

#include <sepol/policydb.h>
#include <sepol/context.h>
#include "user_internal.h"
#include "seuser_internal.h"
#include "handle.h"
#include "database.h"
#include "debug.h"

int semanage_seuser_query(semanage_handle_t * handle,
			  const semanage_seuser_key_t * key,
			  semanage_seuser_t ** response)
{

	dbase_config_t *dconfig = semanage_seuser_dbase_policy(handle);
	return dbase_query(handle, dconfig, key, response);
}

int semanage_seuser_exists(semanage_handle_t * handle,
			   const semanage_seuser_key_t * key, int *response)
{

	dbase_config_t *dconfig = semanage_seuser_dbase_policy(handle);
	return dbase_exists(handle, dconfig, key, response);
}

int semanage_seuser_count(semanage_handle_t * handle, unsigned int *response)
{

	dbase_config_t *dconfig = semanage_seuser_dbase_policy(handle);
	return dbase_count(handle, dconfig, response);
}

int semanage_seuser_iterate(semanage_handle_t * handle,
			    int (*handler) (const semanage_seuser_t * record,
					    void *varg), void *handler_arg)
{

	dbase_config_t *dconfig = semanage_seuser_dbase_policy(handle);
	return dbase_iterate(handle, dconfig, handler, handler_arg);
}


int semanage_seuser_list(semanage_handle_t * handle,
			 semanage_seuser_t *** records, unsigned int *count)
{

	dbase_config_t *dconfig = semanage_seuser_dbase_policy(handle);
	return dbase_list(handle, dconfig, records, count);
}
