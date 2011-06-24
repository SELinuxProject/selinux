/* Copyright (C) 2005 Red Hat, Inc. */

#include <semanage/handle.h>
#include "semanage_store.h"
#include "semanage_conf.h"
#include "database.h"
#include "debug.h"

static int assert_init(semanage_handle_t * handle, dbase_config_t * dconfig)
{

	if (dconfig->dtable == NULL) {

		ERR(handle,
		    "A direct or server connection is needed "
		    "to use this function - please call "
		    "the corresponding connect() method");
		return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}

static int enter_ro(semanage_handle_t * handle, dbase_config_t * dconfig)
{

	if (assert_init(handle, dconfig) < 0)
		goto err;

	if (!handle->is_in_transaction &&
	    handle->conf->store_type == SEMANAGE_CON_DIRECT) {

		if (semanage_get_active_lock(handle) < 0) {
			ERR(handle, "could not get the active lock");
			goto err;
		}
	}

	if (dconfig->dtable->cache(handle, dconfig->dbase) < 0)
		goto err;

	return STATUS_SUCCESS;

      err:
	ERR(handle, "could not enter read-only section");
	return STATUS_ERR;
}

static inline int exit_ro(semanage_handle_t * handle)
{

	int commit_num = handle->funcs->get_serial(handle);

	if (!handle->is_in_transaction &&
	    handle->conf->store_type == SEMANAGE_CON_DIRECT)
		semanage_release_active_lock(handle);

	return commit_num;
}

static int enter_rw(semanage_handle_t * handle, dbase_config_t * dconfig)
{

	if (assert_init(handle, dconfig) < 0)
		goto err;

	if (!handle->is_in_transaction) {
		ERR(handle, "this operation requires a transaction");
		goto err;
	}

	if (dconfig->dtable->cache(handle, dconfig->dbase) < 0)
		goto err;

	return STATUS_SUCCESS;

      err:
	ERR(handle, "could not enter read-write section");
	return STATUS_ERR;
}

int dbase_modify(semanage_handle_t * handle,
		 dbase_config_t * dconfig,
		 const record_key_t * key, const record_t * data)
{

	if (enter_rw(handle, dconfig) < 0)
		return STATUS_ERR;

	if (dconfig->dtable->modify(handle, dconfig->dbase, key, data) < 0)
		return STATUS_ERR;

	return STATUS_SUCCESS;
}

int dbase_set(semanage_handle_t * handle,
	      dbase_config_t * dconfig,
	      const record_key_t * key, const record_t * data)
{

	if (enter_rw(handle, dconfig) < 0)
		return STATUS_ERR;

	if (dconfig->dtable->set(handle, dconfig->dbase, key, data) < 0)
		return STATUS_ERR;

	return STATUS_SUCCESS;
}

int dbase_del(semanage_handle_t * handle,
	      dbase_config_t * dconfig, const record_key_t * key)
{

	if (enter_rw(handle, dconfig) < 0)
		return STATUS_ERR;

	if (dconfig->dtable->del(handle, dconfig->dbase, key) < 0)
		return STATUS_ERR;

	return STATUS_SUCCESS;
}

int dbase_query(semanage_handle_t * handle,
		dbase_config_t * dconfig,
		const record_key_t * key, record_t ** response)
{

	if (enter_ro(handle, dconfig) < 0)
		return STATUS_ERR;

	if (dconfig->dtable->query(handle, dconfig->dbase, key, response) < 0) {
		exit_ro(handle);
		return STATUS_ERR;
	}

	return exit_ro(handle);
}

int dbase_exists(semanage_handle_t * handle,
		 dbase_config_t * dconfig,
		 const record_key_t * key, int *response)
{

	if (enter_ro(handle, dconfig) < 0)
		return STATUS_ERR;

	if (dconfig->dtable->exists(handle, dconfig->dbase, key, response) < 0) {
		exit_ro(handle);
		return STATUS_ERR;
	}

	return exit_ro(handle);
}

int dbase_count(semanage_handle_t * handle,
		dbase_config_t * dconfig, unsigned int *response)
{

	if (enter_ro(handle, dconfig) < 0)
		return STATUS_ERR;

	if (dconfig->dtable->count(handle, dconfig->dbase, response) < 0) {
		exit_ro(handle);
		return STATUS_ERR;
	}

	return exit_ro(handle);
}

int dbase_iterate(semanage_handle_t * handle,
		  dbase_config_t * dconfig,
		  int (*fn) (const record_t * record,
			     void *fn_arg), void *fn_arg)
{

	if (enter_ro(handle, dconfig) < 0)
		return STATUS_ERR;

	if (dconfig->dtable->iterate(handle, dconfig->dbase, fn, fn_arg) < 0) {
		exit_ro(handle);
		return STATUS_ERR;
	}

	return exit_ro(handle);
}

int dbase_list(semanage_handle_t * handle,
	       dbase_config_t * dconfig,
	       record_t *** records, unsigned int *count)
{

	if (enter_ro(handle, dconfig) < 0)
		return STATUS_ERR;

	if (dconfig->dtable->list(handle, dconfig->dbase, records, count) < 0) {
		exit_ro(handle);
		return STATUS_ERR;
	}

	return exit_ro(handle);
}
