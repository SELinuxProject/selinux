/* Copyright (C) 2005 Red Hat, Inc. */

struct semanage_seuser;
struct semanage_seuser_key;
typedef struct semanage_seuser_key record_key_t;
typedef struct semanage_seuser record_t;
#define DBASE_RECORD_DEFINED

#include <sepol/policydb.h>
#include <sepol/context.h>
#include <libaudit.h>
#include <errno.h>
#include "user_internal.h"
#include "seuser_internal.h"
#include "handle.h"
#include "database.h"
#include "debug.h"
#include "string.h"
#include <stdlib.h>

static char *semanage_user_roles(semanage_handle_t * handle, const char *sename) {
	char *roles = NULL;
	unsigned int num_roles;
	size_t i;
	size_t size = 0;
	const char **roles_arr;
	semanage_user_key_t *key = NULL;
	semanage_user_t * user;
	if (semanage_user_key_create(handle, sename, &key) >= 0) {
		if (semanage_user_query(handle, key, &user) >= 0) {
			if (semanage_user_get_roles(handle,
						    user,
						    &roles_arr,
						    &num_roles) >= 0) {
				for (i = 0; i<num_roles; i++) {
					size += (strlen(roles_arr[i]) + 1);
				}
				roles = malloc(size);
				if (roles) {
					strcpy(roles,roles_arr[0]);
					for (i = 1; i<num_roles; i++) {
						strcat(roles,",");
						strcat(roles,roles_arr[i]);
					}
				}
			}
			semanage_user_free(user);
		}
		semanage_user_key_free(key);
	}
	return roles;
}

static int semanage_seuser_audit(semanage_handle_t * handle,
			  const semanage_seuser_t * seuser,
			  const semanage_seuser_t * previous,
			  int audit_type,
			  int success) {
	const char *name = NULL;
	const char *sename = NULL;
	char *roles = NULL;
	const char *mls = NULL;
	const char *psename = NULL;
	const char *pmls = NULL;
	char *proles = NULL;
	char msg[1024];
	const char *sep = "-";
	int rc = -1;
	strcpy(msg, "login");
	if (seuser) {
		name = semanage_seuser_get_name(seuser);
		sename = semanage_seuser_get_sename(seuser);
		mls = semanage_seuser_get_mlsrange(seuser);
		roles = semanage_user_roles(handle, sename);
	}
	if (previous) {
		psename = semanage_seuser_get_sename(previous);
		pmls = semanage_seuser_get_mlsrange(previous);
		proles = semanage_user_roles(handle, psename);
	}
	if (audit_type != AUDIT_ROLE_REMOVE) {
		if (sename && (!psename || strcmp(psename, sename) != 0)) {
			strcat(msg,sep);
			strcat(msg,"sename");
			sep = ",";
		}
		if (roles && (!proles || strcmp(proles, roles) != 0)) {
			strcat(msg,sep);
			strcat(msg,"role");
			sep = ",";
		}
		if (mls && (!pmls || strcmp(pmls, mls) != 0)) {
			strcat(msg,sep);
			strcat(msg,"range");
		}
	}

	int fd = audit_open();
	if (fd < 0)
	{
		/* If kernel doesn't support audit, bail out */
		if (errno == EINVAL || errno == EPROTONOSUPPORT || errno == EAFNOSUPPORT) {
			rc = 0;
			goto err;
		}
		rc = fd;
		goto err;
	}
	audit_log_semanage_message(fd, audit_type, NULL, msg, name, 0, sename, roles, mls, psename, proles, pmls, NULL, NULL,NULL, success);
	rc = 0;
err:
	audit_close(fd);
	free(roles);
	free(proles);
	return rc;
}

int semanage_seuser_modify_local(semanage_handle_t * handle,
				 const semanage_seuser_key_t * key,
				 const semanage_seuser_t * data)
{
	int rc;
	void *callback = (void *) handle->msg_callback;
	dbase_config_t *dconfig = semanage_seuser_dbase_local(handle);
	const char *sename = semanage_seuser_get_sename(data);
	const char *mls_range = semanage_seuser_get_mlsrange(data);
	semanage_seuser_t *previous = NULL;
	semanage_seuser_t *new = NULL;

	if (!sename) {
		errno=EINVAL;
		return -1;
	}
	rc = semanage_seuser_clone(handle, data, &new);
	if (rc < 0) {
		goto err;
	}

	if (!mls_range && semanage_mls_enabled(handle)) {
		semanage_user_key_t *ukey = NULL;
		semanage_user_t *u = NULL;
		rc = semanage_user_key_create(handle, sename, &ukey);
		if (rc < 0)
			goto err;

		rc = semanage_user_query(handle, ukey, &u);
		semanage_user_key_free(ukey);
		if (rc >= 0 ) {
			mls_range = semanage_user_get_mlsrange(u);
			rc = semanage_seuser_set_mlsrange(handle, new, mls_range);
			semanage_user_free(u);
		}
		if (rc < 0)
			goto err;
	}

	handle->msg_callback = NULL;
	(void) semanage_seuser_query(handle, key, &previous);
	handle->msg_callback = callback;
	rc = dbase_modify(handle, dconfig, key, new);
	if (semanage_seuser_audit(handle, new, previous, AUDIT_ROLE_ASSIGN, rc == 0) < 0)
		rc = -1;
err:
	if (previous)
		semanage_seuser_free(previous);
	semanage_seuser_free(new);
	return rc;
}

int semanage_seuser_del_local(semanage_handle_t * handle,
			      const semanage_seuser_key_t * key)
{
	int rc;
	semanage_seuser_t *seuser = NULL;
	dbase_config_t *dconfig = semanage_seuser_dbase_local(handle);
	rc = dbase_del(handle, dconfig, key);
	semanage_seuser_query(handle, key, &seuser);
	if (semanage_seuser_audit(handle, NULL, seuser, AUDIT_ROLE_REMOVE, rc == 0) < 0)
		rc = -1;
	if (seuser)
		semanage_seuser_free(seuser);
	return rc;
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
