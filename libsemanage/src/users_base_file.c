/* Copyright (C) 2005 Red Hat, Inc. */

struct semanage_user_base;
struct semanage_user_key;
typedef struct semanage_user_base record_t;
typedef struct semanage_user_key record_key_t;
#define DBASE_RECORD_DEFINED

struct dbase_file;
typedef struct dbase_file dbase_t;
#define DBASE_DEFINED

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <semanage/handle.h>
#include "user_internal.h"
#include "database_file.h"
#include "parse_utils.h"
#include "debug.h"

static int user_base_print(semanage_handle_t * handle,
			   semanage_user_base_t * user, FILE * str)
{

	const char **roles = NULL;
	unsigned int i, nroles;

	const char *name = semanage_user_base_get_name(user);
	const char *mls_level = semanage_user_base_get_mlslevel(user);
	const char *mls_range = semanage_user_base_get_mlsrange(user);

	if (fprintf(str, "user %s roles { ", name) < 0)
		goto err;

	if (semanage_user_base_get_roles(handle, user, &roles, &nroles) < 0)
		goto err;

	for (i = 0; i < nroles; i++) {
		if (fprintf(str, "%s ", roles[i]) < 0)
			goto err;
	}

	if (fprintf(str, "} ") < 0)
		goto err;

	/* MLS */
	if (mls_level != NULL && mls_range != NULL)
		if (fprintf(str, "level %s range %s", mls_level, mls_range) < 0)
			goto err;

	if (fprintf(str, ";\n") < 0)
		goto err;

	free(roles);
	return STATUS_SUCCESS;

      err:
	free(roles);
	ERR(handle, "could not print user %s to stream", name);
	return STATUS_ERR;
}

static int user_base_parse(semanage_handle_t * handle,
			   parse_info_t * info, semanage_user_base_t * user)
{

	int islist = 0;
	char *str = NULL;
	char *start;
	char *name_str = NULL;

	if (parse_skip_space(handle, info) < 0)
		goto err;
	if (!info->ptr)
		goto last;

	/* Parse user header */
	if (parse_assert_str(handle, info, "user") < 0)
		goto err;
	if (parse_assert_space(handle, info) < 0)
		goto err;

	/* Parse user name */
	if (parse_fetch_string(handle, info, &name_str, ' ', 0) < 0)
		goto err;

	if (semanage_user_base_set_name(handle, user, name_str) < 0) {
		free(name_str);
		goto err;
	}
	free(name_str);

	if (parse_assert_space(handle, info) < 0)
		goto err;
	if (parse_assert_str(handle, info, "roles") < 0)
		goto err;
	if (parse_assert_space(handle, info) < 0)
		goto err;

	islist = (parse_optional_ch(info, '{') != STATUS_NODATA);

	/* For each role, loop */
	do {
		char delim;

		if (parse_skip_space(handle, info) < 0)
			goto err;
		if (parse_assert_noeof(handle, info) < 0)
			goto err;

		start = info->ptr;
		while (*(info->ptr) &&
		       *(info->ptr) != ';' &&
		       *(info->ptr) != '}' && !isspace(*(info->ptr)))
			info->ptr++;

		delim = *(info->ptr);
		*(info->ptr)++ = '\0';

		if (semanage_user_base_add_role(handle, user, start) < 0)
			goto err;

		if (delim && !isspace(delim)) {
			if (islist && delim == '}')
				break;
			else if (!islist && delim == ';')
				goto skip_semicolon;
			else
				goto err;
		}

		if (parse_skip_space(handle, info) < 0)
			goto err;
		if (parse_optional_ch(info, ';') != STATUS_NODATA)
			goto skip_semicolon;
		if (parse_optional_ch(info, '}') != STATUS_NODATA)
			islist = 0;

	} while (islist);

	/* Handle mls */
	/* Parse level header */
	if (parse_skip_space(handle, info) < 0)
		goto err;
	if (parse_optional_str(info, "level") == STATUS_NODATA)
		goto semicolon;
	if (parse_assert_space(handle, info) < 0)
		goto err;

	/* NOTE: does not allow spaces/multiline */
	if (parse_fetch_string(handle, info, &str, ' ', 0) < 0)
		goto err;
	if (semanage_user_base_set_mlslevel(handle, user, str) < 0)
		goto err;
	free(str);
	str = NULL;

	/* Parse range header */
	if (parse_assert_space(handle, info) < 0)
		goto err;
	if (parse_assert_str(handle, info, "range") < 0)
		goto err;
	if (parse_assert_space(handle, info) < 0)
		goto err;

	if (parse_fetch_string(handle, info, &str, ';', 1) < 0)
		goto err;
	if (semanage_user_base_set_mlsrange(handle, user, str) < 0)
		goto err;

	free(str);
	str = NULL;

	/* Check for semicolon */
      semicolon:
	if (parse_skip_space(handle, info) < 0)
		goto err;
	if (parse_assert_ch(handle, info, ';') < 0)
		goto err;

      skip_semicolon:
	return STATUS_SUCCESS;

      last:
	parse_dispose_line(info);
	return STATUS_NODATA;

      err:
	ERR(handle, "could not parse user record");
	free(str);
	parse_dispose_line(info);
	return STATUS_ERR;
}

/* USER BASE record: FILE extension: method table */
record_file_table_t SEMANAGE_USER_BASE_FILE_RTABLE = {
	.parse = user_base_parse,
	.print = user_base_print,
};

int user_base_file_dbase_init(semanage_handle_t * handle,
			      const char *path_ro,
			      const char *path_rw,
			      dbase_config_t * dconfig)
{

	if (dbase_file_init(handle,
			    path_ro,
			    path_rw,
			    &SEMANAGE_USER_BASE_RTABLE,
			    &SEMANAGE_USER_BASE_FILE_RTABLE,
			    &dconfig->dbase) < 0)
		return STATUS_ERR;

	dconfig->dtable = &SEMANAGE_FILE_DTABLE;
	return STATUS_SUCCESS;
}

void user_base_file_dbase_release(dbase_config_t * dconfig)
{

	dbase_file_release(dconfig->dbase);
}
