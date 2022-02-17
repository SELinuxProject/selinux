/* Copyright (C) 2005 Red Hat, Inc. */

struct semanage_seuser;
struct semanage_seuser_key;
typedef struct semanage_seuser record_t;
typedef struct semanage_seuser_key record_key_t;
#define DBASE_RECORD_DEFINED

struct dbase_file;
typedef struct dbase_file dbase_t;
#define DBASE_DEFINED

#include <stdlib.h>
#include <stdio.h>

#include "seuser_internal.h"
#include "database_file.h"
#include "parse_utils.h"
#include "debug.h"
#include "handle.h"

static int seuser_print(semanage_handle_t * handle,
			semanage_seuser_t * seuser, FILE * str)
{

	const char *name = semanage_seuser_get_name(seuser);
	const char *sename = semanage_seuser_get_sename(seuser);
	const char *mls = semanage_seuser_get_mlsrange(seuser);

	if (fprintf(str, "%s:%s", name, sename) < 0)
		goto err;

	if (mls != NULL && fprintf(str, ":%s", mls) < 0)
		goto err;

	fprintf(str, "\n");
	return STATUS_SUCCESS;

      err:
	ERR(handle, "could not print seuser %s to stream", name);
	return STATUS_ERR;
}

static int seuser_parse(semanage_handle_t * handle,
			parse_info_t * info, semanage_seuser_t * seuser)
{

	char *str = NULL;

	if (parse_skip_space(handle, info) < 0)
		goto err;
	if (!info->ptr)
		goto last;

	/* Extract name */
	if (parse_fetch_string(handle, info, &str, ':', 1) < 0)
		goto err;
	if (semanage_seuser_set_name(handle, seuser, str) < 0)
		goto err;
	free(str);
	str = NULL;

	if (parse_skip_space(handle, info) < 0)
		goto err;
	if (parse_assert_ch(handle, info, ':') < 0)
		goto err;
	if (parse_skip_space(handle, info) < 0)
		goto err;

	/* Extract sename */
	if (parse_fetch_string(handle, info, &str, ':', 1) < 0)
		goto err;
	if (semanage_seuser_set_sename(handle, seuser, str) < 0)
		goto err;
	free(str);
	str = NULL;

	if (parse_skip_space(handle, info) < 0)
		goto err;
	if (parse_optional_ch(info, ':') == STATUS_NODATA)
		goto out;
	if (parse_skip_space(handle, info) < 0)
		goto err;

	/* NOTE: does not allow spaces/multiline */
	if (parse_fetch_string(handle, info, &str, ' ', 0) < 0)
		goto err;

	if (semanage_seuser_set_mlsrange(handle, seuser, str) < 0)
		goto err;
	free(str);
	str = NULL;

	if (parse_assert_space(handle, info) < 0)
		goto err;

      out:
	return STATUS_SUCCESS;

      last:
	parse_dispose_line(info);
	return STATUS_NODATA;

      err:
	ERR(handle, "could not parse seuser record");
	free(str);
	parse_dispose_line(info);
	return STATUS_ERR;
}

/* SEUSER RECORD: FILE extension: method table */
record_file_table_t SEMANAGE_SEUSER_FILE_RTABLE = {
	.parse = seuser_parse,
	.print = seuser_print,
};

int seuser_file_dbase_init(semanage_handle_t * handle,
			   const char *path_ro,
			   const char *path_rw,
			   dbase_config_t * dconfig)
{

	if (dbase_file_init(handle,
			    path_ro,
			    path_rw,
			    &SEMANAGE_SEUSER_RTABLE,
			    &SEMANAGE_SEUSER_FILE_RTABLE, &dconfig->dbase) < 0)
		return STATUS_ERR;

	dconfig->dtable = &SEMANAGE_FILE_DTABLE;
	return STATUS_SUCCESS;
}

void seuser_file_dbase_release(dbase_config_t * dconfig)
{

	dbase_file_release(dconfig->dbase);
}
