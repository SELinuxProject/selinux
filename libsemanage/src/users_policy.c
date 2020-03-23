/* Copyright (C) 2005 Red Hat, Inc. */

struct semanage_user;
struct semanage_user_key;
typedef struct semanage_user_key record_key_t;
typedef struct semanage_user record_t;
#define DBASE_RECORD_DEFINED

#include "user_internal.h"
#include "handle.h"
#include "database.h"

int semanage_user_query(semanage_handle_t * handle,
			const semanage_user_key_t * key,
			semanage_user_t ** response)
{

	dbase_config_t *dconfig = semanage_user_dbase_policy(handle);
	return dbase_query(handle, dconfig, key, response);
}


int semanage_user_exists(semanage_handle_t * handle,
			 const semanage_user_key_t * key, int *response)
{

	dbase_config_t *dconfig = semanage_user_dbase_policy(handle);
	return dbase_exists(handle, dconfig, key, response);
}


int semanage_user_count(semanage_handle_t * handle, unsigned int *response)
{

	dbase_config_t *dconfig = semanage_user_dbase_policy(handle);
	return dbase_count(handle, dconfig, response);
}

int semanage_user_iterate(semanage_handle_t * handle,
			  int (*handler) (const semanage_user_t * record,
					  void *varg), void *handler_arg)
{

	dbase_config_t *dconfig = semanage_user_dbase_policy(handle);
	return dbase_iterate(handle, dconfig, handler, handler_arg);
}

int semanage_user_list(semanage_handle_t * handle,
		       semanage_user_t *** records, unsigned int *count)
{

	dbase_config_t *dconfig = semanage_user_dbase_policy(handle);
	return dbase_list(handle, dconfig, records, count);
}
