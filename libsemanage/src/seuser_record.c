/* Copyright (C) 2005 Red Hat, Inc. */

/* Object: semanage_seuser_t (Unix User)
 * Object: semanage_seuser_key_t (Unix User Key)
 * Implements: record_t (Database Record)
 * Implements: record_key_t (Database Record Key)
 */

struct semanage_seuser;
struct semanage_seuser_key;
typedef struct semanage_seuser record_t;
typedef struct semanage_seuser_key record_key_t;
#define DBASE_RECORD_DEFINED

#include <stdlib.h>
#include <string.h>
#include "seuser_internal.h"
#include "debug.h"
#include <semanage/handle.h>
#include "database.h"

struct semanage_seuser {
	/* This user's name */
	char *name;

	/* This user's corresponding 
	 * seuser ("role set") */
	char *sename;

	/* This user's mls range (only required for mls) */
	char *mls_range;
};

struct semanage_seuser_key {
	/* This user's name */
	char *name;
};

int semanage_seuser_key_create(semanage_handle_t * handle,
			       const char *name,
			       semanage_seuser_key_t ** key_ptr)
{

	semanage_seuser_key_t *tmp_key = (semanage_seuser_key_t *)
	    malloc(sizeof(semanage_seuser_key_t));

	if (!tmp_key) {
		ERR(handle, "out of memory, could not create seuser key");
		return STATUS_ERR;
	}
	tmp_key->name = strdup(name);
	if (!tmp_key->name) {
		ERR(handle, "out of memory, could not create seuser key");
		free(tmp_key);
		return STATUS_ERR;
	}

	*key_ptr = tmp_key;
	return STATUS_SUCCESS;
}


int semanage_seuser_key_extract(semanage_handle_t * handle,
				const semanage_seuser_t * seuser,
				semanage_seuser_key_t ** key_ptr)
{

	if (semanage_seuser_key_create(handle, seuser->name, key_ptr) < 0)
		goto err;

	return STATUS_SUCCESS;

      err:
	ERR(handle, "could not extract seuser key from record");
	return STATUS_ERR;
}


void semanage_seuser_key_free(semanage_seuser_key_t * key)
{
	free(key->name);
	free(key);
}


int semanage_seuser_compare(const semanage_seuser_t * seuser,
			    const semanage_seuser_key_t * key)
{

	return strcmp(seuser->name, key->name);
}


int semanage_seuser_compare2(const semanage_seuser_t * seuser,
			     const semanage_seuser_t * seuser2)
{

	return strcmp(seuser->name, seuser2->name);
}


static int semanage_seuser_compare2_qsort(const semanage_seuser_t ** seuser,
					  const semanage_seuser_t ** seuser2)
{

	return strcmp((*seuser)->name, (*seuser2)->name);
}

/* Name */
const char *semanage_seuser_get_name(const semanage_seuser_t * seuser)
{

	return seuser->name;
}


int semanage_seuser_set_name(semanage_handle_t * handle,
			     semanage_seuser_t * seuser, const char *name)
{

	char *tmp_name = strdup(name);
	if (!tmp_name) {
		ERR(handle, "out of memory, could not set seuser (Unix) name");
		return STATUS_ERR;
	}
	free(seuser->name);
	seuser->name = tmp_name;
	return STATUS_SUCCESS;
}


/* Selinux Name */
const char *semanage_seuser_get_sename(const semanage_seuser_t * seuser)
{

	return seuser->sename;
}


int semanage_seuser_set_sename(semanage_handle_t * handle,
			       semanage_seuser_t * seuser, const char *sename)
{

	char *tmp_sename = strdup(sename);
	if (!tmp_sename) {
		ERR(handle,
		    "out of memory, could not set seuser (SELinux) name");
		return STATUS_ERR;
	}
	free(seuser->sename);
	seuser->sename = tmp_sename;
	return STATUS_SUCCESS;
}


/* MLS Range */
const char *semanage_seuser_get_mlsrange(const semanage_seuser_t * seuser)
{

	return seuser->mls_range;
}


int semanage_seuser_set_mlsrange(semanage_handle_t * handle,
				 semanage_seuser_t * seuser,
				 const char *mls_range)
{

	char *tmp_mls_range = strdup(mls_range);
	if (!tmp_mls_range) {
		ERR(handle, "out of memory, could not set seuser MLS range");
		return STATUS_ERR;
	}
	free(seuser->mls_range);
	seuser->mls_range = tmp_mls_range;
	return STATUS_SUCCESS;
}


/* Create */
int semanage_seuser_create(semanage_handle_t * handle,
			   semanage_seuser_t ** seuser_ptr)
{

	semanage_seuser_t *seuser =
	    (semanage_seuser_t *) malloc(sizeof(semanage_seuser_t));

	if (!seuser) {
		ERR(handle, "out of memory, could not create seuser");
		return STATUS_ERR;
	}

	seuser->name = NULL;
	seuser->sename = NULL;
	seuser->mls_range = NULL;

	*seuser_ptr = seuser;
	return STATUS_SUCCESS;
}


/* Deep copy clone */
int semanage_seuser_clone(semanage_handle_t * handle,
			  const semanage_seuser_t * seuser,
			  semanage_seuser_t ** seuser_ptr)
{

	semanage_seuser_t *new_seuser = NULL;

	if (semanage_seuser_create(handle, &new_seuser) < 0)
		goto err;

	if (semanage_seuser_set_name(handle, new_seuser, seuser->name) < 0)
		goto err;

	if (semanage_seuser_set_sename(handle, new_seuser, seuser->sename) < 0)
		goto err;

	if (seuser->mls_range &&
	    (semanage_seuser_set_mlsrange(handle, new_seuser, seuser->mls_range)
	     < 0))
		goto err;

	*seuser_ptr = new_seuser;
	return STATUS_SUCCESS;

      err:
	ERR(handle, "could not clone seuser");
	semanage_seuser_free(new_seuser);
	return STATUS_ERR;
}


/* Destroy */
void semanage_seuser_free(semanage_seuser_t * seuser)
{

	if (!seuser)
		return;

	free(seuser->name);
	free(seuser->sename);
	free(seuser->mls_range);
	free(seuser);
}


/* Record base functions */
record_table_t SEMANAGE_SEUSER_RTABLE = {
	.create = semanage_seuser_create,
	.key_extract = semanage_seuser_key_extract,
	.key_free = semanage_seuser_key_free,
	.clone = semanage_seuser_clone,
	.compare = semanage_seuser_compare,
	.compare2 = semanage_seuser_compare2,
	.compare2_qsort = semanage_seuser_compare2_qsort,
	.free = semanage_seuser_free,
};
