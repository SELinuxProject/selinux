/* Copyright (C) 2017 Mellanox Technologies Inc. */

struct semanage_ibendport;
struct semanage_ibendport_key;
typedef struct semanage_ibendport record_t;
typedef struct semanage_ibendport_key record_key_t;
#define DBASE_RECORD_DEFINED

struct dbase_file;
typedef struct dbase_file dbase_t;
#define DBASE_DEFINED

#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <semanage/handle.h>
#include "ibendport_internal.h"
#include "database_file.h"
#include "parse_utils.h"
#include "debug.h"

static int ibendport_print(semanage_handle_t *handle,
			   const semanage_ibendport_t *ibendport,
			   FILE *str)
{
	const semanage_context_t *con;
	char *con_str = NULL;
	char *ibdev_name_str = NULL;
	int port = semanage_ibendport_get_port(ibendport);

	if (semanage_ibendport_get_ibdev_name(handle, ibendport, &ibdev_name_str) != 0)
		goto err;

	con = semanage_ibendport_get_con(ibendport);

	if (fprintf(str, "ibendportcon %s ", ibdev_name_str) < 0)
		goto err;

	if (fprintf(str, "%d ", port) < 0)
		goto err;

	if (semanage_context_to_string(handle, con, &con_str) < 0)
		goto err;
	if (fprintf(str, "%s\n", con_str) < 0)
		goto err;

	free(ibdev_name_str);
	free(con_str);
	return STATUS_SUCCESS;

err:
	ERR(handle, "could not print ibendport (%s) %u to stream",
	    ibdev_name_str, port);
	free(ibdev_name_str);
	free(con_str);
	return STATUS_ERR;
}

static int ibendport_parse(semanage_handle_t *handle,
			   parse_info_t *info,
			   semanage_ibendport_t *ibendport)
{
	int port;
	char *str = NULL;
	semanage_context_t *con = NULL;

	if (parse_skip_space(handle, info) < 0)
		goto err;
	if (!info->ptr)
		goto last;

	/* Header */
	if (parse_assert_str(handle, info, "ibendportcon") < 0)
		goto err;
	if (parse_assert_space(handle, info) < 0)
		goto err;

	/* IB Device Name */
	if (parse_fetch_string(handle, info, &str, ' ', 0) < 0)
		goto err;
	if (semanage_ibendport_set_ibdev_name(handle, ibendport, str) < 0)
		goto err;
	free(str);
	str = NULL;

	/* Port */
	if (parse_assert_space(handle, info) < 0)
		goto err;
	if (parse_fetch_int(handle, info, &port, ' ') < 0)
		goto err;
	semanage_ibendport_set_port(ibendport, port);

	/* context */
	if (parse_assert_space(handle, info) < 0)
		goto err;
	if (parse_fetch_string(handle, info, &str, ' ', 0) < 0)
		goto err;
	if (semanage_context_from_string(handle, str, &con) < 0) {
		ERR(handle, "invalid security context \"%s\" (%s: %u)\n%s",
		    str, info->filename, info->lineno, info->orig_line);
		goto err;
	}
	if (!con) {
		ERR(handle, "<<none>> context is not valid for ibendport (%s: %u):\n%s",
		    info->filename, info->lineno, info->orig_line);
		goto err;
	}
	free(str);
	str = NULL;

	if (semanage_ibendport_set_con(handle, ibendport, con) < 0)
		goto err;

	if (parse_assert_space(handle, info) < 0)
		goto err;

	semanage_context_free(con);
	return STATUS_SUCCESS;

last:
	parse_dispose_line(info);
	return STATUS_NODATA;

err:
	ERR(handle, "could not parse ibendport record");
	free(str);
	semanage_context_free(con);
	parse_dispose_line(info);
	return STATUS_ERR;
}

/* IBENDPORT RECORD: FILE extension: method table */
static const record_file_table_t SEMANAGE_IBENDPORT_FILE_RTABLE = {
	.parse = ibendport_parse,
	.print = ibendport_print,
};

int ibendport_file_dbase_init(semanage_handle_t *handle,
			      const char *path_ro,
			      const char *path_rw,
			      dbase_config_t *dconfig)
{
	if (dbase_file_init(handle,
			    path_ro,
			    path_rw,
			    &SEMANAGE_IBENDPORT_RTABLE,
			    &SEMANAGE_IBENDPORT_FILE_RTABLE, &dconfig->dbase) < 0)
		return STATUS_ERR;

	dconfig->dtable = &SEMANAGE_FILE_DTABLE;
	return STATUS_SUCCESS;
}

void ibendport_file_dbase_release(dbase_config_t *dconfig)
{
	dbase_file_release(dconfig->dbase);
}
