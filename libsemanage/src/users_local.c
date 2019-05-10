/* Copyright (C) 2005 Red Hat, Inc. */

struct semanage_user;
struct semanage_user_key;
typedef struct semanage_user_key record_key_t;
typedef struct semanage_user record_t;
#define DBASE_RECORD_DEFINED

#include <string.h>
#include <stdlib.h>
#include "user_internal.h"
#include "seuser_internal.h"
#include "handle.h"
#include "database.h"
#include "errno.h"
#include "debug.h"

int semanage_user_modify_local(semanage_handle_t * handle,
			       const semanage_user_key_t * key,
			       const semanage_user_t * data)
{

	dbase_config_t *dconfig = semanage_user_dbase_local(handle);
	return dbase_modify(handle, dconfig, key, data);
}

static int lookup_seuser(semanage_handle_t * handle, const semanage_user_key_t *k) {
	semanage_user_t *user;
	semanage_seuser_t **records;
	const char *name;
	const char *sename;
	unsigned int count;
	size_t i;
	int rc = 0;
	if (semanage_user_query(handle, k, &user) < 0)
		return 0;
	name = semanage_user_get_name(user);
	semanage_seuser_list_local(handle,
				   &records,
				   &count);
	for(i = 0; i < count; i++) {
		sename = semanage_seuser_get_sename(records[i]);
		if (strcmp(name, sename) == 0) {
			errno = EINVAL;
			ERR(handle, "%s is being used by %s login record",
			    sename, semanage_seuser_get_name(records[i]));
			rc = -1;
		}
	}
	for(i = 0; i < count; i++)
		semanage_seuser_free(records[i]);
	free(records);
	semanage_user_free(user);
	if (rc)
		errno = EINVAL;
	return rc;
}

int semanage_user_del_local(semanage_handle_t * handle,
			    const semanage_user_key_t * key)
{
	if (lookup_seuser(handle, key))
		return -1;

	dbase_config_t *dconfig = semanage_user_dbase_local(handle);
	return dbase_del(handle, dconfig, key);
}

int semanage_user_query_local(semanage_handle_t * handle,
			      const semanage_user_key_t * key,
			      semanage_user_t ** response)
{

	dbase_config_t *dconfig = semanage_user_dbase_local(handle);
	return dbase_query(handle, dconfig, key, response);
}

int semanage_user_exists_local(semanage_handle_t * handle,
			       const semanage_user_key_t * key, int *response)
{

	dbase_config_t *dconfig = semanage_user_dbase_local(handle);
	return dbase_exists(handle, dconfig, key, response);
}

int semanage_user_count_local(semanage_handle_t * handle,
			      unsigned int *response)
{

	dbase_config_t *dconfig = semanage_user_dbase_local(handle);
	return dbase_count(handle, dconfig, response);
}

int semanage_user_iterate_local(semanage_handle_t * handle,
				int (*handler) (const semanage_user_t * record,
						void *varg), void *handler_arg)
{

	dbase_config_t *dconfig = semanage_user_dbase_local(handle);
	return dbase_iterate(handle, dconfig, handler, handler_arg);
}

int semanage_user_list_local(semanage_handle_t * handle,
			     semanage_user_t *** records, unsigned int *count)
{

	dbase_config_t *dconfig = semanage_user_dbase_local(handle);
	return dbase_list(handle, dconfig, records, count);
}
