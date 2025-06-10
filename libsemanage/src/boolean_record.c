/* Copyright (C) 2005 Red Hat, Inc. */

/* Object: semanage_bool_t (Policy Boolean)
 * Object: semanage_bool_key_t (Policy Boolean Key)
 * Implements: record_t (Database Record)
 * Implements: record_key_t (Database Record Key)
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <sepol/boolean_record.h>

typedef sepol_bool_t semanage_bool_t;
typedef sepol_bool_key_t semanage_bool_key_t;
#define _SEMANAGE_BOOL_DEFINED_

typedef semanage_bool_t record_t;
typedef semanage_bool_key_t record_key_t;
#define DBASE_RECORD_DEFINED

#include "boolean_internal.h"
#include "handle.h"
#include "database.h"
#include <selinux/selinux.h>

/* Key */
int semanage_bool_key_create(semanage_handle_t * handle,
			     const char *name, semanage_bool_key_t ** key)
{

	return sepol_bool_key_create(handle->sepolh, name, key);
}

int semanage_bool_key_extract(semanage_handle_t * handle,
			      const semanage_bool_t * boolean,
			      semanage_bool_key_t ** key)
{

	return sepol_bool_key_extract(handle->sepolh, boolean, key);
}


void semanage_bool_key_free(semanage_bool_key_t * key)
{
	sepol_bool_key_free(key);
}


int semanage_bool_compare(const semanage_bool_t * boolean,
			  const semanage_bool_key_t * key)
{

	return sepol_bool_compare(boolean, key);
}


int semanage_bool_compare2(const semanage_bool_t * boolean,
			   const semanage_bool_t * boolean2)
{

	return sepol_bool_compare2(boolean, boolean2);
}


static int semanage_bool_compare2_qsort(const void *p1, const void *p2)
{
	const semanage_bool_t *const *boolean1 = p1;
	const semanage_bool_t *const *boolean2 = p2;

	return sepol_bool_compare2(*boolean1, *boolean2);
}

/* Name */
const char *semanage_bool_get_name(const semanage_bool_t * boolean)
{

	return sepol_bool_get_name(boolean);
}


int semanage_bool_set_name(semanage_handle_t * handle,
			   semanage_bool_t * boolean, const char *name)
{
	int rc = -1;
	const char *prefix = semanage_root();
	const char *storename = handle->conf->store_path;
	const char *selinux_root = selinux_policy_root();
	char *oldroot;
	char *olddir;
	char *subname = NULL;
	char *newroot = NULL;
	char *end;

	if (!selinux_root)
		return -1;

	oldroot = strdup(selinux_root);
	if (!oldroot)
		return -1;
	olddir = strdup(oldroot);
	if (!olddir)
		goto out;
	end = strrchr(olddir, '/');
	if (!end)
		goto out;
	end++;
	*end = '\0';
	rc = asprintf(&newroot, "%s%s%s", prefix, olddir, storename);
	if (rc < 0) {
		newroot = NULL;
		goto out;
	}

	if (strcmp(oldroot, newroot)) {
		rc = selinux_set_policy_root(newroot);
		if (rc)
			goto out;
	}

	subname = selinux_boolean_sub(name);
	if (!subname) {
		rc = -1;
		goto out;
	}

	if (strcmp(oldroot, newroot)) {
		rc = selinux_set_policy_root(oldroot);
		if (rc)
			goto out;
	}

	rc = sepol_bool_set_name(handle->sepolh, boolean, subname);
out:
	free(subname);
	free(oldroot);
	free(olddir);
	free(newroot);
	return rc;
}


/* Value */
int semanage_bool_get_value(const semanage_bool_t * boolean)
{

	return sepol_bool_get_value(boolean);
}


void semanage_bool_set_value(semanage_bool_t * boolean, int value)
{

	sepol_bool_set_value(boolean, value);
}


/* Create/Clone/Destroy */
int semanage_bool_create(semanage_handle_t * handle,
			 semanage_bool_t ** bool_ptr)
{

	return sepol_bool_create(handle->sepolh, bool_ptr);
}


int semanage_bool_clone(semanage_handle_t * handle,
			const semanage_bool_t * boolean,
			semanage_bool_t ** bool_ptr)
{

	return sepol_bool_clone(handle->sepolh, boolean, bool_ptr);
}


void semanage_bool_free(semanage_bool_t * boolean)
{

	sepol_bool_free(boolean);
}


/* Record base functions */
const record_table_t SEMANAGE_BOOL_RTABLE = {
	.create = semanage_bool_create,
	.key_extract = semanage_bool_key_extract,
	.key_free = semanage_bool_key_free,
	.clone = semanage_bool_clone,
	.compare = semanage_bool_compare,
	.compare2 = semanage_bool_compare2,
	.compare2_qsort = semanage_bool_compare2_qsort,
	.free = semanage_bool_free,
};
