/* Copyright (C) 2005 Red Hat, Inc. */

struct semanage_bool;
struct semanage_bool_key;
typedef struct semanage_bool record_t;
typedef struct semanage_bool_key record_key_t;
#define DBASE_RECORD_DEFINED

struct dbase_file;
typedef struct dbase_file dbase_t;
#define DBASE_DEFINED

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <semanage/handle.h>
#include "boolean_internal.h"
#include "database_file.h"
#include "parse_utils.h"
#include "debug.h"

static int bool_print(semanage_handle_t * handle,
		      semanage_bool_t * boolean, FILE * str)
{

	const char *name = semanage_bool_get_name(boolean);
	int value = semanage_bool_get_value(boolean);

	if (fprintf(str, "%s=%d\n", name, value) < 0) {
		ERR(handle, "could not print boolean %s to stream", name);
		return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}

static int bool_parse(semanage_handle_t * handle,
		      parse_info_t * info, semanage_bool_t * boolean)
{

	int value = 0;
	char *str = NULL;

	if (parse_skip_space(handle, info) < 0)
		goto err;
	if (!info->ptr)
		goto last;

	/* Extract name */
	if (parse_fetch_string(handle, info, &str, '=') < 0)
		goto err;

	if (semanage_bool_set_name(handle, boolean, str) < 0)
		goto err;
	free(str);
	str = NULL;

	/* Assert = */
	if (parse_skip_space(handle, info) < 0)
		goto err;
	if (parse_assert_ch(handle, info, '=') < 0)
		goto err;

	/* Extract value */
	if (parse_skip_space(handle, info) < 0)
		goto err;
	if (parse_optional_str(info, "true") != STATUS_NODATA)
		value = 1;
	else if (parse_optional_str(info, "TRUE") != STATUS_NODATA)
		value = 1;
	else if (parse_optional_str(info, "false") != STATUS_NODATA)
		value = 0;
	else if (parse_optional_str(info, "FALSE") != STATUS_NODATA)
		value = 0;
	else if (parse_fetch_int(handle, info, &value, ' ') < 0)
		goto err;

	if (value != 0 && value != 1) {
		ERR(handle, "invalid boolean value for \"%s\": %u "
		    "(%s: %u)\n%s", semanage_bool_get_name(boolean),
		    value, info->filename, info->lineno, info->orig_line);
		goto err;
	}
	semanage_bool_set_value(boolean, value);

	if (parse_assert_space(handle, info) < 0)
		goto err;

	return STATUS_SUCCESS;

      last:
	parse_dispose_line(info);
	return STATUS_NODATA;

      err:
	ERR(handle, "could not parse boolean record");
	free(str);
	parse_dispose_line(info);
	return STATUS_ERR;
}

/* BOOL RECORD: FILE extension: method table */
record_file_table_t SEMANAGE_BOOL_FILE_RTABLE = {
	.parse = bool_parse,
	.print = bool_print,
};

int bool_file_dbase_init(semanage_handle_t * handle,
			 const char *path_ro,
			 const char *path_rw,
			 dbase_config_t * dconfig)
{

	if (dbase_file_init(handle,
			    path_ro,
			    path_rw,
			    &SEMANAGE_BOOL_RTABLE,
			    &SEMANAGE_BOOL_FILE_RTABLE, &dconfig->dbase) < 0)
		return STATUS_ERR;

	dconfig->dtable = &SEMANAGE_FILE_DTABLE;
	return STATUS_SUCCESS;
}

void bool_file_dbase_release(dbase_config_t * dconfig)
{

	dbase_file_release(dconfig->dbase);
}
