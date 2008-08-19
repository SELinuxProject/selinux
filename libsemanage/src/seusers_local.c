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

int semanage_seuser_modify_local(semanage_handle_t * handle,
				 const semanage_seuser_key_t * key,
				 const semanage_seuser_t * data)
{

	dbase_config_t *dconfig = semanage_seuser_dbase_local(handle);
	return dbase_modify(handle, dconfig, key, data);
}

int semanage_seuser_del_local(semanage_handle_t * handle,
			      const semanage_seuser_key_t * key)
{

	dbase_config_t *dconfig = semanage_seuser_dbase_local(handle);
	return dbase_del(handle, dconfig, key);
}

int semanage_seuser_query_local(semanage_handle_t * handle,
				const semanage_seuser_key_t * key,
				semanage_seuser_t ** response)
{

	dbase_config_t *dconfig = semanage_seuser_dbase_local(handle);
	return dbase_query(handle, dconfig, key, response);
}

int semanage_seuser_exists_local(semanage_handle_t * handle,
				 const semanage_seuser_key_t * key,
				 int *response)
{

	dbase_config_t *dconfig = semanage_seuser_dbase_local(handle);
	return dbase_exists(handle, dconfig, key, response);
}

int semanage_seuser_count_local(semanage_handle_t * handle,
				unsigned int *response)
{

	dbase_config_t *dconfig = semanage_seuser_dbase_local(handle);
	return dbase_count(handle, dconfig, response);
}

int semanage_seuser_iterate_local(semanage_handle_t * handle,
				  int (*handler) (const semanage_seuser_t *
						  record, void *varg),
				  void *handler_arg)
{

	dbase_config_t *dconfig = semanage_seuser_dbase_local(handle);
	return dbase_iterate(handle, dconfig, handler, handler_arg);
}

hidden_def(semanage_seuser_iterate_local)

int semanage_seuser_list_local(semanage_handle_t * handle,
			       semanage_seuser_t *** records,
			       unsigned int *count)
{

	dbase_config_t *dconfig = semanage_seuser_dbase_local(handle);
	return dbase_list(handle, dconfig, records, count);
}

struct validate_handler_arg {
	semanage_handle_t *handle;
	const sepol_policydb_t *policydb;
};

static int validate_handler(const semanage_seuser_t * seuser, void *varg)
{

	semanage_user_t *user = NULL;
	semanage_user_key_t *key = NULL;
	int exists, mls_ok;

	/* Unpack varg */
	struct validate_handler_arg *arg = (struct validate_handler_arg *)varg;
	semanage_handle_t *handle = arg->handle;
	const sepol_policydb_t *policydb = arg->policydb;

	/* Unpack seuser */
	const char *name = semanage_seuser_get_name(seuser);
	const char *sename = semanage_seuser_get_sename(seuser);
	const char *mls_range = semanage_seuser_get_mlsrange(seuser);
	const char *user_mls_range;

	/* Make sure the (SElinux) user exists */
	if (semanage_user_key_create(handle, sename, &key) < 0)
		goto err;
	if (semanage_user_exists(handle, key, &exists) < 0)
		goto err;
	if (!exists) {
		ERR(handle, "selinux user %s does not exist", sename);
		goto invalid;
	}

	/* Verify that the mls range is valid, and that it's contained
	 * within the (SELinux) user mls range. This range is optional */
	if (mls_range && sepol_policydb_mls_enabled(policydb)) {

		if (semanage_user_query(handle, key, &user) < 0)
			goto err;
		user_mls_range = semanage_user_get_mlsrange(user);

		if (sepol_mls_check(handle->sepolh, policydb, mls_range) < 0)
			goto invalid;
		if (sepol_mls_contains(handle->sepolh, policydb,
				       user_mls_range, mls_range, &mls_ok) < 0)
			goto err;

		if (!mls_ok) {
			ERR(handle, "MLS range %s for Unix user %s "
			    "exceeds allowed range %s for SELinux user %s",
			    mls_range, name, user_mls_range, sename);
			goto invalid;
		}

	} else if (mls_range) {
		ERR(handle, "MLS is disabled, but MLS range %s "
		    "was found for Unix user %s", mls_range, name);
		goto invalid;
	}

	semanage_user_key_free(key);
	semanage_user_free(user);
	return 0;

      err:
	ERR(handle, "could not check if seuser mapping for %s is valid", name);
	semanage_user_key_free(key);
	semanage_user_free(user);
	return -1;

      invalid:
	if (mls_range)
		ERR(handle, "seuser mapping [%s -> (%s, %s)] is invalid",
		    name, sename, mls_range);
	else
		ERR(handle, "seuser mapping [%s -> %s] is invalid",
		    name, sename);
	semanage_user_key_free(key);
	semanage_user_free(user);
	return -1;
}

/* This function may not be called outside a transaction, or 
 * it will (1) deadlock, because iterate is not reentrant outside
 * a transaction, and (2) be racy, because it makes multiple dbase calls */

int hidden semanage_seuser_validate_local(semanage_handle_t * handle,
					  const sepol_policydb_t * policydb)
{

	struct validate_handler_arg arg;
	arg.handle = handle;
	arg.policydb = policydb;
	return semanage_seuser_iterate_local(handle, validate_handler, &arg);
}
