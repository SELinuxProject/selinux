/* Copyright (C) 2005 Red Hat, Inc. */

struct semanage_node;
struct semanage_node_key;
typedef struct semanage_node record_t;
typedef struct semanage_node_key record_key_t;
#define DBASE_RECORD_DEFINED

struct dbase_file;
typedef struct dbase_file dbase_t;
#define DBASE_DEFINED

#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <semanage/handle.h>
#include "node_internal.h"
#include "database_file.h"
#include "parse_utils.h"
#include "debug.h"

static int node_print(semanage_handle_t * handle,
		      semanage_node_t * node, FILE * str)
{

	char *con_str = NULL;
	char *addr = NULL;
	char *mask = NULL;

	int proto = semanage_node_get_proto(node);
	const char *proto_str = semanage_node_get_proto_str(proto);
	semanage_context_t *con = semanage_node_get_con(node);

	if (semanage_node_get_addr(handle, node, &addr) < 0)
		goto err;

	if (semanage_node_get_mask(handle, node, &mask) < 0)
		goto err;

	if (semanage_context_to_string(handle, con, &con_str) < 0)
		goto err;

	if (fprintf
	    (str, "nodecon %s %s %s %s\n", proto_str, addr, mask, con_str) < 0)
		goto err;

	free(addr);
	free(mask);
	free(con_str);
	return STATUS_SUCCESS;

      err:
	free(addr);
	free(mask);
	free(con_str);
	ERR(handle, "could not print node to stream");
	return STATUS_ERR;
}

static int node_parse(semanage_handle_t * handle,
		      parse_info_t * info, semanage_node_t * node)
{

	int proto;
	char *str = NULL;
	semanage_context_t *con = NULL;

	if (parse_skip_space(handle, info) < 0)
		goto err;
	if (!info->ptr)
		goto last;

	/* Header */
	if (parse_assert_str(handle, info, "nodecon") < 0)
		goto err;
	if (parse_assert_space(handle, info) < 0)
		goto err;

	/* Protocol */
	if (parse_fetch_string(handle, info, &str, ' ', 0) < 0)
		goto err;
	if (!strcasecmp(str, "ipv4"))
		proto = SEMANAGE_PROTO_IP4;
	else if (!strcasecmp(str, "ipv6"))
		proto = SEMANAGE_PROTO_IP6;
	else {
		ERR(handle, "invalid protocol \"%s\" (%s: %u):\n%s", str,
		    info->filename, info->lineno, info->orig_line);
		goto err;
	}
	free(str);
	str = NULL;

	semanage_node_set_proto(node, proto);

	/* Address */
	if (parse_assert_space(handle, info) < 0)
		goto err;
	if (parse_fetch_string(handle, info, &str, ' ', 0) < 0)
		goto err;
	if (semanage_node_set_addr(handle, node, proto, str) < 0)
		goto err;
	if (parse_assert_space(handle, info) < 0)
		goto err;
	free(str);
	str = NULL;

	/* Netmask */
	if (parse_fetch_string(handle, info, &str, ' ', 0) < 0)
		goto err;
	if (semanage_node_set_mask(handle, node, proto, str) < 0)
		goto err;
	if (parse_assert_space(handle, info) < 0)
		goto err;
	free(str);
	str = NULL;

	/* Port context */
	if (parse_fetch_string(handle, info, &str, ' ', 0) < 0)
		goto err;
	if (semanage_context_from_string(handle, str, &con) < 0) {
		ERR(handle, "invalid security context \"%s\" (%s: %u)\n%s",
		    str, info->filename, info->lineno, info->orig_line);
		goto err;
	}
	if (con == NULL) {
		ERR(handle, "<<none>> context is not valid "
		    "for nodes (%s: %u):\n%s", info->filename,
		    info->lineno, info->orig_line);
		goto err;
	}
	free(str);
	str = NULL;

	if (semanage_node_set_con(handle, node, con) < 0)
		goto err;

	if (parse_assert_space(handle, info) < 0)
		goto err;

	semanage_context_free(con);
	return STATUS_SUCCESS;

      last:
	parse_dispose_line(info);
	return STATUS_NODATA;

      err:
	ERR(handle, "could not parse node record");
	free(str);
	semanage_context_free(con);
	parse_dispose_line(info);
	return STATUS_ERR;
}

/* NODE RECORD: FILE extension: method table */
record_file_table_t SEMANAGE_NODE_FILE_RTABLE = {
	.parse = node_parse,
	.print = node_print,
};

int node_file_dbase_init(semanage_handle_t * handle,
			 const char *path_ro,
			 const char *path_rw,
			 dbase_config_t * dconfig)
{

	if (dbase_file_init(handle,
			    path_ro,
			    path_rw,
			    &SEMANAGE_NODE_RTABLE,
			    &SEMANAGE_NODE_FILE_RTABLE, &dconfig->dbase) < 0)
		return STATUS_ERR;

	dconfig->dtable = &SEMANAGE_FILE_DTABLE;
	return STATUS_SUCCESS;
}

void node_file_dbase_release(dbase_config_t * dconfig)
{

	dbase_file_release(dconfig->dbase);
}
