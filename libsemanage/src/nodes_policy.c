/* Copyright (C) 2005 Red Hat, Inc. */

struct semanage_node;
struct semanage_node_key;
typedef struct semanage_node_key record_key_t;
typedef struct semanage_node record_t;
#define DBASE_RECORD_DEFINED

#include "node_internal.h"
#include "handle.h"
#include "database.h"

int semanage_node_query(semanage_handle_t * handle,
			const semanage_node_key_t * key,
			semanage_node_t ** response)
{

	dbase_config_t *dconfig = semanage_node_dbase_policy(handle);
	return dbase_query(handle, dconfig, key, response);
}

int semanage_node_exists(semanage_handle_t * handle,
			 const semanage_node_key_t * key, int *response)
{

	dbase_config_t *dconfig = semanage_node_dbase_policy(handle);
	return dbase_exists(handle, dconfig, key, response);
}

int semanage_node_count(semanage_handle_t * handle, unsigned int *response)
{

	dbase_config_t *dconfig = semanage_node_dbase_policy(handle);
	return dbase_count(handle, dconfig, response);
}

int semanage_node_iterate(semanage_handle_t * handle,
			  int (*handler) (const semanage_node_t * record,
					  void *varg), void *handler_arg)
{

	dbase_config_t *dconfig = semanage_node_dbase_policy(handle);
	return dbase_iterate(handle, dconfig, handler, handler_arg);
}

int semanage_node_list(semanage_handle_t * handle,
		       semanage_node_t *** records, unsigned int *count)
{

	dbase_config_t *dconfig = semanage_node_dbase_policy(handle);
	return dbase_list(handle, dconfig, records, count);
}
