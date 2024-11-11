/* Copyright (C) 2005 Red Hat, Inc. */

struct semanage_bool;
struct semanage_bool_key;
typedef struct semanage_bool record_t;
typedef struct semanage_bool_key record_key_t;
#define DBASE_RECORD_DEFINED

struct dbase_activedb;
typedef struct dbase_activedb dbase_t;
#define DBASE_DEFINED

#include <stdlib.h>
#include <string.h>
#include <selinux/selinux.h>
#include <semanage/handle.h>
#include "boolean_internal.h"
#include "database_activedb.h"
#include "parse_utils.h"
#include "debug.h"

static int bool_read_list(semanage_handle_t * handle,
			  semanage_bool_t *** booleans, unsigned int *count)
{

	semanage_bool_t **tmp_booleans = NULL;
	unsigned int tmp_count = 0;
	int i;

	char **names = NULL;
	int len = 0;

	/* Fetch boolean names */
	if (security_get_boolean_names(&names, &len) < 0) {
		ERR(handle, "could not get list of boolean names");
		goto err;
	}

	/* Allocate a sufficiently large array */
	tmp_booleans = malloc(sizeof(semanage_bool_t *) * len);
	if (tmp_booleans == NULL)
		goto omem;

	/* Create records one by one */
	for (i = 0; i < len; i++) {

		int value;

		if (semanage_bool_create(handle, &tmp_booleans[i]) < 0)
			goto err;
		tmp_count++;

		if (semanage_bool_set_name(handle,
					   tmp_booleans[i], names[i]) < 0)
			goto err;

		value = security_get_boolean_active(names[i]);
		if (value < 0) {
			ERR(handle, "could not get the value "
			    "for boolean %s", names[i]);
			goto err;
		}

		semanage_bool_set_value(tmp_booleans[i], value);
	}

	/* Success */
	for (i = 0; i < len; i++)
		free(names[i]);
	free(names);
	*booleans = tmp_booleans;
	*count = tmp_count;
	return STATUS_SUCCESS;

	/* Failure */
      omem:
	ERR(handle, "out of memory");

      err:
	ERR(handle, "could not read boolean list");
	for (i = 0; i < len; i++)
		free(names[i]);
	free(names);
	for (i = 0; (unsigned int)i < tmp_count; i++)
		semanage_bool_free(tmp_booleans[i]);
	free(tmp_booleans);
	return STATUS_ERR;
}

static int bool_commit_list(semanage_handle_t * handle,
			    semanage_bool_t ** booleans, unsigned int count)
{

	SELboolean *blist = NULL;
	const char *name;
	unsigned int bcount = 0;
	unsigned int i;
	int curvalue, newvalue;

	/* Allocate a sufficiently large array */
	blist = malloc(sizeof(SELboolean) * count);
	if (blist == NULL)
		goto omem;

	/* Populate array */
	for (i = 0; i < count; i++) {
		name = semanage_bool_get_name(booleans[i]);
		if (!name)
			goto omem;
		newvalue = semanage_bool_get_value(booleans[i]);
		curvalue = security_get_boolean_active(name);
		if (newvalue == curvalue)
			continue;
		blist[bcount].name = strdup(name);
		if (blist[bcount].name == NULL)
			goto omem;
		blist[bcount].value = newvalue;
		bcount++;
	}

	/* Commit */
	if (security_set_boolean_list(bcount, blist, 0) < 0) {
		ERR(handle, "libselinux commit failed");
		goto err;
	}

	for (i = 0; i < bcount; i++)
		free(blist[i].name);
	free(blist);
	return STATUS_SUCCESS;

      omem:
	ERR(handle, "out of memory");

      err:
	ERR(handle, "could not commit boolean list");
	for (i = 0; i < bcount; i++)
		free(blist[i].name);
	free(blist);
	return STATUS_ERR;
}

/* BOOL RECORD: ACTIVEDB extension: method table */
static const record_activedb_table_t SEMANAGE_BOOL_ACTIVEDB_RTABLE = {
	.read_list = bool_read_list,
	.commit_list = bool_commit_list,
};

int bool_activedb_dbase_init(semanage_handle_t * handle,
			     dbase_config_t * dconfig)
{

	if (dbase_activedb_init(handle,
				&SEMANAGE_BOOL_RTABLE,
				&SEMANAGE_BOOL_ACTIVEDB_RTABLE,
				&dconfig->dbase) < 0)
		return STATUS_ERR;

	dconfig->dtable = &SEMANAGE_ACTIVEDB_DTABLE;
	return STATUS_SUCCESS;
}

void bool_activedb_dbase_release(dbase_config_t * dconfig)
{

	dbase_activedb_release(dconfig->dbase);
}
