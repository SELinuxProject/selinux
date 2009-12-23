/* Copyright (C) 2005 Red Hat, Inc. */

struct semanage_port;
struct semanage_port_key;
typedef struct semanage_port record_t;
typedef struct semanage_port_key record_key_t;
#define DBASE_RECORD_DEFINED

struct dbase_file;
typedef struct dbase_file dbase_t;
#define DBASE_DEFINED

#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <semanage/handle.h>
#include "port_internal.h"
#include "context_internal.h"
#include "database_file.h"
#include "parse_utils.h"
#include "debug.h"

static int port_print(semanage_handle_t * handle,
		      semanage_port_t * port, FILE * str)
{

	char *con_str = NULL;

	int low = semanage_port_get_low(port);
	int high = semanage_port_get_high(port);
	int proto = semanage_port_get_proto(port);
	const char *proto_str = semanage_port_get_proto_str(proto);
	semanage_context_t *con = semanage_port_get_con(port);

	if (fprintf(str, "portcon %s ", proto_str) < 0)
		goto err;

	if (low == high) {
		if (fprintf(str, "%d ", low) < 0)
			goto err;
	} else {
		if (fprintf(str, "%d - %d ", low, high) < 0)
			goto err;
	}

	if (semanage_context_to_string(handle, con, &con_str) < 0)
		goto err;
	if (fprintf(str, "%s\n", con_str) < 0)
		goto err;

	free(con_str);
	return STATUS_SUCCESS;

      err:
	ERR(handle, "could not print port range %u - %u (%s) to stream",
	    low, high, proto_str);
	free(con_str);
	return STATUS_ERR;
}

static int port_parse(semanage_handle_t * handle,
		      parse_info_t * info, semanage_port_t * port)
{

	int low, high;
	char *str = NULL;
	semanage_context_t *con = NULL;

	if (parse_skip_space(handle, info) < 0)
		goto err;
	if (!info->ptr)
		goto last;

	/* Header */
	if (parse_assert_str(handle, info, "portcon") < 0)
		goto err;
	if (parse_assert_space(handle, info) < 0)
		goto err;

	/* Protocol */
	if (parse_fetch_string(handle, info, &str, ' ') < 0)
		goto err;
	if (!strcasecmp(str, "tcp"))
		semanage_port_set_proto(port, SEMANAGE_PROTO_TCP);
	else if (!strcasecmp(str, "udp"))
		semanage_port_set_proto(port, SEMANAGE_PROTO_UDP);
	else {
		ERR(handle, "invalid protocol \"%s\" (%s: %u):\n%s", str,
		    info->filename, info->lineno, info->orig_line);
		goto err;
	}
	free(str);
	str = NULL;

	/* Range/Port */
	if (parse_assert_space(handle, info) < 0)
		goto err;
	if (parse_fetch_int(handle, info, &low, '-') < 0)
		goto err;

	/* If range (-) does not follow immediately, require a space 
	 * In other words, the space here is optional, but only
	 * in the ranged case, not in the single port case,
	 * so do a custom test */
	if (*(info->ptr) && *(info->ptr) != '-') {
		if (parse_assert_space(handle, info) < 0)
			goto err;
	}

	if (parse_optional_ch(info, '-') != STATUS_NODATA) {

		if (parse_skip_space(handle, info) < 0)
			goto err;
		if (parse_fetch_int(handle, info, &high, ' ') < 0)
			goto err;
		if (parse_assert_space(handle, info) < 0)
			goto err;
		semanage_port_set_range(port, low, high);
	} else
		semanage_port_set_port(port, low);

	/* Port context */
	if (parse_fetch_string(handle, info, &str, ' ') < 0)
		goto err;
	if (semanage_context_from_string(handle, str, &con) < 0) {
		ERR(handle, "invalid security context \"%s\" (%s: %u)\n%s",
		    str, info->filename, info->lineno, info->orig_line);
		goto err;
	}
	if (con == NULL) {
		ERR(handle, "<<none>> context is not valid "
		    "for ports (%s: %u):\n%s", info->filename,
		    info->lineno, info->orig_line);
		goto err;
	}
	free(str);
	str = NULL;

	if (semanage_port_set_con(handle, port, con) < 0)
		goto err;

	if (parse_assert_space(handle, info) < 0)
		goto err;

	semanage_context_free(con);
	return STATUS_SUCCESS;

      last:
	parse_dispose_line(info);
	return STATUS_NODATA;

      err:
	ERR(handle, "could not parse port record");
	free(str);
	semanage_context_free(con);
	parse_dispose_line(info);
	return STATUS_ERR;
}

/* PORT RECORD: FILE extension: method table */
record_file_table_t SEMANAGE_PORT_FILE_RTABLE = {
	.parse = port_parse,
	.print = port_print,
};

int port_file_dbase_init(semanage_handle_t * handle,
			 const char *path_ro,
			 const char *path_rw,
			 dbase_config_t * dconfig)
{

	if (dbase_file_init(handle,
			    path_ro,
			    path_rw,
			    &SEMANAGE_PORT_RTABLE,
			    &SEMANAGE_PORT_FILE_RTABLE, &dconfig->dbase) < 0)
		return STATUS_ERR;

	dconfig->dtable = &SEMANAGE_FILE_DTABLE;
	return STATUS_SUCCESS;
}

void port_file_dbase_release(dbase_config_t * dconfig)
{

	dbase_file_release(dconfig->dbase);
}
