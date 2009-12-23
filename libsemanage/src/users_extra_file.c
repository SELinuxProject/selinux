/* Copyright (C) 2005 Red Hat, Inc. */

struct semanage_user_extra;
struct semanage_user_key;
typedef struct semanage_user_extra record_t;
typedef struct semanage_user_key record_key_t;
#define DBASE_RECORD_DEFINED

struct dbase_file;
typedef struct dbase_file dbase_t;
#define DBASE_DEFINED

#include <stdlib.h>
#include <stdio.h>
#include <strings.h>

#include "user_internal.h"
#include "database_file.h"
#include "parse_utils.h"
#include "debug.h"
#include "handle.h"

static int user_extra_print(semanage_handle_t * handle,
			    semanage_user_extra_t * user_extra, FILE * str)
{

	const char *name = semanage_user_extra_get_name(user_extra);
	const char *prefix = semanage_user_extra_get_prefix(user_extra);

	if (fprintf(str, "user %s prefix %s;\n", name, prefix) < 0)
		goto err;

	return STATUS_SUCCESS;

      err:
	ERR(handle, "could not print user extra data "
	    "for %s to stream", name);
	return STATUS_ERR;
}

static int user_extra_parse(semanage_handle_t * handle,
			    parse_info_t * info,
			    semanage_user_extra_t * user_extra)
{

	char *str = NULL;

	if (parse_skip_space(handle, info) < 0)
		goto err;
	if (!info->ptr)
		goto last;

	/* User string */
	if (parse_assert_str(handle, info, "user") < 0)
		goto err;
	if (parse_assert_space(handle, info) < 0)
		goto err;

	/* Extract name */
	if (parse_fetch_string(handle, info, &str, ' ') < 0)
		goto err;
	if (semanage_user_extra_set_name(handle, user_extra, str) < 0)
		goto err;
	free(str);
	str = NULL;

	/* Prefix string */
	if (parse_assert_space(handle, info) < 0)
		goto err;
	if (parse_assert_str(handle, info, "prefix") < 0)
		goto err;
	if (parse_assert_space(handle, info) < 0)
		goto err;

	/* Extract prefix */
	if (parse_fetch_string(handle, info, &str, ';') < 0)
		goto err;
	if (semanage_user_extra_set_prefix(handle, user_extra, str) < 0)
		goto err;
	free(str);
	str = NULL;

	/* Semicolon */
	if (parse_skip_space(handle, info) < 0)
		goto err;
	if (parse_assert_ch(handle, info, ';') < 0)
		goto err;

	return STATUS_SUCCESS;

      last:
	parse_dispose_line(info);
	return STATUS_NODATA;

      err:
	ERR(handle, "could not parse user extra data");
	free(str);
	parse_dispose_line(info);
	return STATUS_ERR;
}

/* USER EXTRA RECORD: FILE extension: method table */
record_file_table_t SEMANAGE_USER_EXTRA_FILE_RTABLE = {
	.parse = user_extra_parse,
	.print = user_extra_print,
};

int user_extra_file_dbase_init(semanage_handle_t * handle,
			       const char *path_ro,
			       const char *path_rw,
			       dbase_config_t * dconfig)
{

	if (dbase_file_init(handle,
			    path_ro,
			    path_rw,
			    &SEMANAGE_USER_EXTRA_RTABLE,
			    &SEMANAGE_USER_EXTRA_FILE_RTABLE,
			    &dconfig->dbase) < 0)
		return STATUS_ERR;

	dconfig->dtable = &SEMANAGE_FILE_DTABLE;
	return STATUS_SUCCESS;
}

void user_extra_file_dbase_release(dbase_config_t * dconfig)
{

	dbase_file_release(dconfig->dbase);
}
