/* Copyright (C) 2017 Mellanox Technologies Inc. */

struct semanage_ibpkey;
struct semanage_ibpkey_key;
typedef struct semanage_ibpkey_key record_key_t;
typedef struct semanage_ibpkey record_t;
#define DBASE_RECORD_DEFINED

#include "ibpkey_internal.h"
#include "handle.h"
#include "database.h"

int semanage_ibpkey_query(semanage_handle_t *handle,
			  const semanage_ibpkey_key_t *key,
			  semanage_ibpkey_t **response)
{
	dbase_config_t *dconfig = semanage_ibpkey_dbase_policy(handle);

	return dbase_query(handle, dconfig, key, response);
}

int semanage_ibpkey_exists(semanage_handle_t *handle,
			   const semanage_ibpkey_key_t *key, int *response)
{
	dbase_config_t *dconfig = semanage_ibpkey_dbase_policy(handle);

	return dbase_exists(handle, dconfig, key, response);
}

int semanage_ibpkey_count(semanage_handle_t *handle, unsigned int *response)
{
	dbase_config_t *dconfig = semanage_ibpkey_dbase_policy(handle);

	return dbase_count(handle, dconfig, response);
}

int semanage_ibpkey_iterate(semanage_handle_t *handle,
			    int (*handler)(const semanage_ibpkey_t *record,
					   void *varg), void *handler_arg)
{
	dbase_config_t *dconfig = semanage_ibpkey_dbase_policy(handle);

	return dbase_iterate(handle, dconfig, handler, handler_arg);
}

int semanage_ibpkey_list(semanage_handle_t *handle,
			 semanage_ibpkey_t ***records, unsigned int *count)
{
	dbase_config_t *dconfig = semanage_ibpkey_dbase_policy(handle);

	return dbase_list(handle, dconfig, records, count);
}
