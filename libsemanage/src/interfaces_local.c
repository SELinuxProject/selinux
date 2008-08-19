/* Copyright (C) 2005 Red Hat, Inc. */

struct semanage_iface;
struct semanage_iface_key;
typedef struct semanage_iface_key record_key_t;
typedef struct semanage_iface record_t;
#define DBASE_RECORD_DEFINED

#include "iface_internal.h"
#include "handle.h"
#include "database.h"

int semanage_iface_modify_local(semanage_handle_t * handle,
				const semanage_iface_key_t * key,
				const semanage_iface_t * data)
{

	dbase_config_t *dconfig = semanage_iface_dbase_local(handle);
	return dbase_modify(handle, dconfig, key, data);
}

int semanage_iface_del_local(semanage_handle_t * handle,
			     const semanage_iface_key_t * key)
{

	dbase_config_t *dconfig = semanage_iface_dbase_local(handle);
	return dbase_del(handle, dconfig, key);
}

int semanage_iface_query_local(semanage_handle_t * handle,
			       const semanage_iface_key_t * key,
			       semanage_iface_t ** response)
{

	dbase_config_t *dconfig = semanage_iface_dbase_local(handle);
	return dbase_query(handle, dconfig, key, response);
}

int semanage_iface_exists_local(semanage_handle_t * handle,
				const semanage_iface_key_t * key, int *response)
{

	dbase_config_t *dconfig = semanage_iface_dbase_local(handle);
	return dbase_exists(handle, dconfig, key, response);
}

int semanage_iface_count_local(semanage_handle_t * handle,
			       unsigned int *response)
{

	dbase_config_t *dconfig = semanage_iface_dbase_local(handle);
	return dbase_count(handle, dconfig, response);
}

int semanage_iface_iterate_local(semanage_handle_t * handle,
				 int (*handler) (const semanage_iface_t *
						 record, void *varg),
				 void *handler_arg)
{

	dbase_config_t *dconfig = semanage_iface_dbase_local(handle);
	return dbase_iterate(handle, dconfig, handler, handler_arg);
}

int semanage_iface_list_local(semanage_handle_t * handle,
			      semanage_iface_t *** records, unsigned int *count)
{

	dbase_config_t *dconfig = semanage_iface_dbase_local(handle);
	return dbase_list(handle, dconfig, records, count);
}
