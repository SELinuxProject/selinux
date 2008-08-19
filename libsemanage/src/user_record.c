/* Copyright (C) 2005 Red Hat, Inc. */

/* Object: semanage_user_t (SELinux User/Class)
 * Object: semanage_user_key_t (SELinux User/Class Key)
 * Implements: record_t (Database Record)
 * Implements: record_key_t (Database Record Key)
 */

#include <sepol/user_record.h>

typedef sepol_user_key_t semanage_user_key_t;
#define _SEMANAGE_USER_KEY_DEFINED_

struct semanage_user;
typedef struct semanage_user record_t;
typedef semanage_user_key_t record_key_t;
#define DBASE_RECORD_DEFINED

#include <stdlib.h>
#include <string.h>
#include "user_internal.h"
#include "handle.h"
#include "database.h"
#include "debug.h"

struct semanage_user {
	char *name;
	semanage_user_base_t *base;
	semanage_user_extra_t *extra;
};

/* Key */
int semanage_user_key_create(semanage_handle_t * handle,
			     const char *name, semanage_user_key_t ** key)
{

	return sepol_user_key_create(handle->sepolh, name, key);
}

hidden_def(semanage_user_key_create)

int semanage_user_key_extract(semanage_handle_t * handle,
			      const semanage_user_t * user,
			      semanage_user_key_t ** key)
{

	return semanage_user_base_key_extract(handle, user->base, key);
}

hidden_def(semanage_user_key_extract)

void semanage_user_key_free(semanage_user_key_t * key)
{

	sepol_user_key_free(key);
}

hidden_def(semanage_user_key_free)

hidden void semanage_user_key_unpack(const semanage_user_key_t * key,
				     const char **name)
{

	sepol_user_key_unpack(key, name);
}

int semanage_user_compare(const semanage_user_t * user,
			  const semanage_user_key_t * key)
{

	const char *name;
	sepol_user_key_unpack(key, &name);
	return strcmp(user->name, name);
}

hidden_def(semanage_user_compare)

int semanage_user_compare2(const semanage_user_t * user,
			   const semanage_user_t * user2)
{

	return strcmp(user->name, user2->name);
}

hidden_def(semanage_user_compare2)

static int semanage_user_compare2_qsort(const semanage_user_t ** user,
					const semanage_user_t ** user2)
{

	return strcmp((*user)->name, (*user2)->name);
}

/* Name */
const char *semanage_user_get_name(const semanage_user_t * user)
{
	return user->name;
}

hidden_def(semanage_user_get_name)

int semanage_user_set_name(semanage_handle_t * handle,
			   semanage_user_t * user, const char *name)
{

	char *tmp_name = strdup(name);
	if (!tmp_name)
		goto omem;

	if (semanage_user_base_set_name(handle, user->base, name) < 0)
		goto err;

	if (semanage_user_extra_set_name(handle, user->extra, name) < 0)
		goto err;

	free(user->name);
	user->name = tmp_name;
	return STATUS_SUCCESS;

      omem:
	ERR(handle, "out of memory");

      err:
	ERR(handle, "could not set user name to %s", name);
	free(tmp_name);
	return STATUS_ERR;
}

hidden_def(semanage_user_set_name)

/* Labeling prefix */
const char *semanage_user_get_prefix(const semanage_user_t * user)
{

	return semanage_user_extra_get_prefix(user->extra);
}

int semanage_user_set_prefix(semanage_handle_t * handle,
			     semanage_user_t * user, const char *name)
{

	return semanage_user_extra_set_prefix(handle, user->extra, name);
}

/* MLS */
const char *semanage_user_get_mlslevel(const semanage_user_t * user)
{

	return semanage_user_base_get_mlslevel(user->base);
}

hidden_def(semanage_user_get_mlslevel)

int semanage_user_set_mlslevel(semanage_handle_t * handle,
			       semanage_user_t * user, const char *mls_level)
{

	return semanage_user_base_set_mlslevel(handle, user->base, mls_level);
}

hidden_def(semanage_user_set_mlslevel)

const char *semanage_user_get_mlsrange(const semanage_user_t * user)
{

	return semanage_user_base_get_mlsrange(user->base);
}

hidden_def(semanage_user_get_mlsrange)

int semanage_user_set_mlsrange(semanage_handle_t * handle,
			       semanage_user_t * user, const char *mls_range)
{

	return semanage_user_base_set_mlsrange(handle, user->base, mls_range);
}

hidden_def(semanage_user_set_mlsrange)

/* Role management */
int semanage_user_get_num_roles(const semanage_user_t * user)
{

	return semanage_user_base_get_num_roles(user->base);
}

int semanage_user_add_role(semanage_handle_t * handle,
			   semanage_user_t * user, const char *role)
{

	return semanage_user_base_add_role(handle, user->base, role);
}

hidden_def(semanage_user_add_role)

void semanage_user_del_role(semanage_user_t * user, const char *role)
{

	semanage_user_base_del_role(user->base, role);
}

int semanage_user_has_role(const semanage_user_t * user, const char *role)
{

	return semanage_user_base_has_role(user->base, role);
}

int semanage_user_get_roles(semanage_handle_t * handle,
			    const semanage_user_t * user,
			    const char ***roles_arr, unsigned int *num_roles)
{

	return semanage_user_base_get_roles(handle, user->base, roles_arr,
					    num_roles);
}

hidden_def(semanage_user_get_roles)

int semanage_user_set_roles(semanage_handle_t * handle,
			    semanage_user_t * user,
			    const char **roles_arr, unsigned int num_roles)
{

	return semanage_user_base_set_roles(handle, user->base, roles_arr,
					    num_roles);
}

/* Create/Clone/Destroy */
int semanage_user_create(semanage_handle_t * handle,
			 semanage_user_t ** user_ptr)
{

	semanage_user_t *tmp_user = calloc(1, sizeof(semanage_user_t));
	if (!tmp_user)
		goto omem;

	if (semanage_user_base_create(handle, &tmp_user->base) < 0)
		goto err;
	if (semanage_user_extra_create(handle, &tmp_user->extra) < 0)
		goto err;

	/* Initialize the prefix for migration purposes */
	if (semanage_user_extra_set_prefix(handle, tmp_user->extra, "user") < 0)
		goto err;

	*user_ptr = tmp_user;
	return STATUS_SUCCESS;

      omem:
	ERR(handle, "out of memory");

      err:
	ERR(handle, "could not create user record");
	semanage_user_free(tmp_user);
	return STATUS_ERR;
}

hidden_def(semanage_user_create)

int semanage_user_clone(semanage_handle_t * handle,
			const semanage_user_t * user,
			semanage_user_t ** user_ptr)
{

	semanage_user_t *tmp_user = calloc(1, sizeof(semanage_user_t));
	if (!tmp_user)
		goto omem;

	/* Clone base and extra records */
	if (semanage_user_base_clone(handle, user->base, &tmp_user->base) < 0)
		goto err;
	if (semanage_user_extra_clone(handle, user->extra, &tmp_user->extra) <
	    0)
		goto err;

	/* Set the shared name */
	if (semanage_user_set_name(handle, tmp_user, user->name) < 0)
		goto err;

	*user_ptr = tmp_user;
	return STATUS_SUCCESS;

      omem:
	ERR(handle, "out of memory");

      err:
	ERR(handle, "could not clone user record");
	semanage_user_free(tmp_user);
	return STATUS_ERR;
}

hidden_def(semanage_user_clone)

void semanage_user_free(semanage_user_t * user)
{

	if (!user)
		return;

	semanage_user_base_free(user->base);
	semanage_user_extra_free(user->extra);
	free(user->name);
	free(user);
}

hidden_def(semanage_user_free)

/* Join properties */
hidden int semanage_user_join(semanage_handle_t * handle,
			      const semanage_user_base_t * record1,
			      const semanage_user_extra_t * record2,
			      semanage_user_t ** result)
{

	const char *name;
	semanage_user_t *tmp_user = calloc(1, sizeof(semanage_user_t));
	if (!tmp_user)
		goto omem;

	/* Set the shared name from one of the records 
	 * (at least one is available) */
	if (record1 == NULL)
		name = semanage_user_extra_get_name(record2);
	else
		name = semanage_user_base_get_name(record1);

	/* Join base record if it exists, create a blank one otherwise */
	if (record1) {
		if (semanage_user_base_clone(handle, record1, &tmp_user->base) <
		    0)
			goto err;
	} else {
		if (semanage_user_base_create(handle, &tmp_user->base) < 0)
			goto err;
		if (semanage_user_base_set_name(handle, tmp_user->base, name) <
		    0)
			goto err;
	}

	/* Join extra record if it exists, create a blank one otherwise */
	if (record2) {
		if (semanage_user_extra_clone(handle, record2, &tmp_user->extra)
		    < 0)
			goto err;
	} else {
		if (semanage_user_extra_create(handle, &tmp_user->extra) < 0)
			goto err;
		if (semanage_user_extra_set_name(handle, tmp_user->extra, name)
		    < 0)
			goto err;
		if (semanage_user_extra_set_prefix
		    (handle, tmp_user->extra, "user") < 0)
			goto err;
	}

	if (semanage_user_set_name(handle, tmp_user, name) < 0)
		goto err;

	*result = tmp_user;
	return STATUS_SUCCESS;

      omem:
	ERR(handle, "out of memory");

      err:
	ERR(handle, "could not join data records for user %s",
	    semanage_user_base_get_name(record1));
	semanage_user_free(tmp_user);
	return STATUS_ERR;
}

hidden int semanage_user_split(semanage_handle_t * handle,
			       const semanage_user_t * record,
			       semanage_user_base_t ** split1,
			       semanage_user_extra_t ** split2)
{

	semanage_user_base_t *tmp_base_user = NULL;
	semanage_user_extra_t *tmp_extra_user = NULL;

	if (semanage_user_base_clone(handle, record->base, &tmp_base_user) < 0)
		goto err;

	if (semanage_user_extra_clone(handle, record->extra, &tmp_extra_user) <
	    0)
		goto err;

	*split1 = tmp_base_user;
	*split2 = tmp_extra_user;
	return STATUS_SUCCESS;

      err:
	ERR(handle, "could not split data records for user %s",
	    semanage_user_get_name(record));
	semanage_user_base_free(tmp_base_user);
	semanage_user_extra_free(tmp_extra_user);
	return STATUS_ERR;
}

/* Record base functions */
record_table_t SEMANAGE_USER_RTABLE = {
	.create = semanage_user_create,
	.key_extract = semanage_user_key_extract,
	.key_free = semanage_user_key_free,
	.clone = semanage_user_clone,
	.compare = semanage_user_compare,
	.compare2 = semanage_user_compare2,
	.compare2_qsort = semanage_user_compare2_qsort,
	.free = semanage_user_free,
};
