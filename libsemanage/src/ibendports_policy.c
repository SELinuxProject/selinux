/* Copyright (C) 2017 Mellanox Technologies Inc */

struct semanage_ibendport;
struct semanage_ibendport_key;
typedef struct semanage_ibendport_key record_key_t;
typedef struct semanage_ibendport record_t;
#define DBASE_RECORD_DEFINED

#include "ibendport_internal.h"
#include "handle.h"
#include "database.h"

int semanage_ibendport_query(semanage_handle_t *handle,
			     const semanage_ibendport_key_t *key,
			     semanage_ibendport_t **response)
{
	dbase_config_t *dconfig = semanage_ibendport_dbase_policy(handle);

	return dbase_query(handle, dconfig, key, response);
}

int semanage_ibendport_exists(semanage_handle_t *handle,
			      const semanage_ibendport_key_t *key,
			      int *response)
{
	dbase_config_t *dconfig = semanage_ibendport_dbase_policy(handle);

	return dbase_exists(handle, dconfig, key, response);
}

int semanage_ibendport_count(semanage_handle_t *handle,
			     unsigned int *response)
{
	dbase_config_t *dconfig = semanage_ibendport_dbase_policy(handle);

	return dbase_count(handle, dconfig, response);
}

int semanage_ibendport_iterate(semanage_handle_t *handle,
			       int (*handler)(const semanage_ibendport_t *record,
					      void *varg), void *handler_arg)
{
	dbase_config_t *dconfig = semanage_ibendport_dbase_policy(handle);

	return dbase_iterate(handle, dconfig, handler, handler_arg);
}

int semanage_ibendport_list(semanage_handle_t *handle,
			    semanage_ibendport_t ***records,
			    unsigned int *count)
{
	dbase_config_t *dconfig = semanage_ibendport_dbase_policy(handle);

	return dbase_list(handle, dconfig, records, count);
}
