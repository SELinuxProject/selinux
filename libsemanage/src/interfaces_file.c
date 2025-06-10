/* Copyright (C) 2005 Red Hat, Inc. */

struct semanage_iface;
struct semanage_iface_key;
typedef struct semanage_iface record_t;
typedef struct semanage_iface_key record_key_t;
#define DBASE_RECORD_DEFINED

struct dbase_file;
typedef struct dbase_file dbase_t;
#define DBASE_DEFINED

#include <stdlib.h>
#include <stdio.h>
#include <semanage/handle.h>
#include "iface_internal.h"
#include "database_file.h"
#include "parse_utils.h"
#include "debug.h"

static int iface_print(semanage_handle_t * handle,
		       const semanage_iface_t * iface, FILE * str)
{

	char *con_str = NULL;

	const char *name = semanage_iface_get_name(iface);
	semanage_context_t *ifcon = semanage_iface_get_ifcon(iface);
	semanage_context_t *msgcon = semanage_iface_get_msgcon(iface);

	if (fprintf(str, "netifcon %s ", name) < 0)
		goto err;

	if (semanage_context_to_string(handle, ifcon, &con_str) < 0)
		goto err;
	if (fprintf(str, "%s ", con_str) < 0)
		goto err;
	free(con_str);
	con_str = NULL;

	if (semanage_context_to_string(handle, msgcon, &con_str) < 0)
		goto err;
	if (fprintf(str, "%s\n", con_str) < 0)
		goto err;
	free(con_str);
	con_str = NULL;

	return STATUS_SUCCESS;

      err:
	ERR(handle, "could not print interface %s to stream", name);
	free(con_str);
	return STATUS_ERR;
}

static int iface_parse(semanage_handle_t * handle,
		       parse_info_t * info, semanage_iface_t * iface)
{

	char *str = NULL;
	semanage_context_t *con = NULL;

	if (parse_skip_space(handle, info) < 0)
		goto err;
	if (!info->ptr)
		goto last;

	/* Header */
	if (parse_assert_str(handle, info, "netifcon") < 0)
		goto err;
	if (parse_assert_space(handle, info) < 0)
		goto err;

	/* Name */
	if (parse_fetch_string(handle, info, &str, ' ', 0) < 0)
		goto err;
	if (semanage_iface_set_name(handle, iface, str) < 0)
		goto err;
	free(str);
	str = NULL;

	/* Interface context */
	if (parse_assert_space(handle, info) < 0)
		goto err;
	if (parse_fetch_string(handle, info, &str, ' ', 0) < 0)
		goto err;
	if (semanage_context_from_string(handle, str, &con) < 0) {
		ERR(handle, "invalid security context \"%s\" (%s: %u)\n%s",
		    str, info->filename, info->lineno, info->orig_line);
		goto err;
	}
	if (con == NULL) {
		ERR(handle, "<<none>> context is not valid for "
		    "interfaces (%s: %u)\n%s", info->filename,
		    info->lineno, info->orig_line);
		goto err;
	}
	free(str);
	str = NULL;

	if (semanage_iface_set_ifcon(handle, iface, con) < 0)
		goto err;
	semanage_context_free(con);
	con = NULL;

	/* Message context */
	if (parse_assert_space(handle, info) < 0)
		goto err;
	if (parse_fetch_string(handle, info, &str, ' ', 0) < 0)
		goto err;
	if (semanage_context_from_string(handle, str, &con) < 0) {
		ERR(handle, "invalid security context \"%s\" (%s: %u)\n%s",
		    str, info->filename, info->lineno, info->orig_line);
		goto err;
	}
	if (con == NULL) {
		ERR(handle, "<<none>> context is not valid for "
		    "interfaces (%s: %u)\n%s", info->filename,
		    info->lineno, info->orig_line);
		goto err;
	}
	free(str);
	str = NULL;

	if (semanage_iface_set_msgcon(handle, iface, con) < 0)
		goto err;
	semanage_context_free(con);
	con = NULL;

	if (parse_assert_space(handle, info) < 0)
		goto err;

	return STATUS_SUCCESS;

      last:
	parse_dispose_line(info);
	return STATUS_NODATA;

      err:
	ERR(handle, "could not parse interface record");
	free(str);
	semanage_context_free(con);
	parse_dispose_line(info);
	return STATUS_ERR;
}

/* IFACE RECORD: FILE extension: method table */
static const record_file_table_t SEMANAGE_IFACE_FILE_RTABLE = {
	.parse = iface_parse,
	.print = iface_print,
};

int iface_file_dbase_init(semanage_handle_t * handle,
			  const char *path_ro,
			  const char *path_rw,
			  dbase_config_t * dconfig)
{

	if (dbase_file_init(handle,
			    path_ro,
			    path_rw,
			    &SEMANAGE_IFACE_RTABLE,
			    &SEMANAGE_IFACE_FILE_RTABLE, &dconfig->dbase) < 0)
		return STATUS_ERR;

	dconfig->dtable = &SEMANAGE_FILE_DTABLE;
	return STATUS_SUCCESS;
}

void iface_file_dbase_release(dbase_config_t * dconfig)
{

	dbase_file_release(dconfig->dbase);
}
