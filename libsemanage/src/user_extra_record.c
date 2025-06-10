/* Copyright (C) 2005 Red Hat, Inc. */

/* Object: semanage_user_extra_t (SELinux User/Class Extra Data)
 * Object: semanage_user_extra_key_t (SELinux User/Class Key)
 * Implements: record_t (Database Record)
 * Implements: record_key_t (Database Record Key)
 */

#include <sepol/user_record.h>

typedef sepol_user_key_t semanage_user_key_t;
#define _SEMANAGE_USER_KEY_DEFINED_

struct semanage_user_extra;
typedef struct semanage_user_extra record_t;
typedef semanage_user_key_t record_key_t;
#define DBASE_RECORD_DEFINED

#include <semanage/handle.h>
#include <stdlib.h>
#include <string.h>
#include "user_internal.h"
#include "debug.h"
#include "database.h"

struct semanage_user_extra {
	/* This user's name */
	char *name;

	/* Labeling prefix */
	char *prefix;
};

static int semanage_user_extra_key_extract(semanage_handle_t * handle,
					   const semanage_user_extra_t *
					   user_extra,
					   semanage_user_key_t ** key_ptr)
{

	if (semanage_user_key_create(handle, user_extra->name, key_ptr) < 0)
		goto err;

	return STATUS_SUCCESS;

      err:
	ERR(handle, "could not extract key from user extra record");
	return STATUS_ERR;
}

static int semanage_user_extra_compare(const semanage_user_extra_t * user_extra,
				       const semanage_user_key_t * key)
{

	const char *name;
	semanage_user_key_unpack(key, &name);

	return strcmp(user_extra->name, name);
}

static int semanage_user_extra_compare2(const semanage_user_extra_t *
					user_extra,
					const semanage_user_extra_t *
					user_extra2)
{

	return strcmp(user_extra->name, user_extra2->name);
}

static int semanage_user_extra_compare2_qsort(const void *p1, const void *p2)
{
	const semanage_user_extra_t *const *user_extra1 = p1;
	const semanage_user_extra_t *const *user_extra2 = p2;

	return semanage_user_extra_compare2(*user_extra1, *user_extra2);
}

/* Name */
 const char *semanage_user_extra_get_name(const semanage_user_extra_t *
						user_extra)
{

	return user_extra->name;
}

 int semanage_user_extra_set_name(semanage_handle_t * handle,
					semanage_user_extra_t * user_extra,
					const char *name)
{

	char *tmp_name = strdup(name);
	if (!tmp_name) {
		ERR(handle, "out of memory, could not set name %s "
		    "for user extra data", name);
		return STATUS_ERR;
	}
	free(user_extra->name);
	user_extra->name = tmp_name;
	return STATUS_SUCCESS;
}

/* Labeling prefix */
 const char *semanage_user_extra_get_prefix(const semanage_user_extra_t *
						  user_extra)
{

	return user_extra->prefix;
}

 int semanage_user_extra_set_prefix(semanage_handle_t * handle,
					  semanage_user_extra_t * user_extra,
					  const char *prefix)
{

	char *tmp_prefix = strdup(prefix);
	if (!tmp_prefix) {
		ERR(handle, "out of memory, could not set prefix %s "
		    "for user %s", prefix, user_extra->name);
		return STATUS_ERR;
	}
	free(user_extra->prefix);
	user_extra->prefix = tmp_prefix;
	return STATUS_SUCCESS;
}

/* Create */
 int semanage_user_extra_create(semanage_handle_t * handle,
				      semanage_user_extra_t ** user_extra_ptr)
{

	semanage_user_extra_t *user_extra =
	    (semanage_user_extra_t *) malloc(sizeof(semanage_user_extra_t));

	if (!user_extra) {
		ERR(handle, "out of memory, could not "
		    "create user extra data record");
		return STATUS_ERR;
	}

	user_extra->name = NULL;
	user_extra->prefix = NULL;

	*user_extra_ptr = user_extra;
	return STATUS_SUCCESS;
}

/* Destroy */
 void semanage_user_extra_free(semanage_user_extra_t * user_extra)
{

	if (!user_extra)
		return;

	free(user_extra->name);
	free(user_extra->prefix);
	free(user_extra);
}

/* Deep copy clone */
 int semanage_user_extra_clone(semanage_handle_t * handle,
				     const semanage_user_extra_t * user_extra,
				     semanage_user_extra_t ** user_extra_ptr)
{

	semanage_user_extra_t *new_user_extra = NULL;

	if (semanage_user_extra_create(handle, &new_user_extra) < 0)
		goto err;

	if (semanage_user_extra_set_name
	    (handle, new_user_extra, user_extra->name) < 0)
		goto err;

	if (semanage_user_extra_set_prefix
	    (handle, new_user_extra, user_extra->prefix) < 0)
		goto err;

	*user_extra_ptr = new_user_extra;
	return STATUS_SUCCESS;

      err:
	ERR(handle, "could not clone extra data for user %s", user_extra->name);
	semanage_user_extra_free(new_user_extra);
	return STATUS_ERR;
}

/* Record base functions */
const record_table_t SEMANAGE_USER_EXTRA_RTABLE = {
	.create = semanage_user_extra_create,
	.key_extract = semanage_user_extra_key_extract,
	.key_free = semanage_user_key_free,
	.clone = semanage_user_extra_clone,
	.compare = semanage_user_extra_compare,
	.compare2 = semanage_user_extra_compare2,
	.compare2_qsort = semanage_user_extra_compare2_qsort,
	.free = semanage_user_extra_free,
};
