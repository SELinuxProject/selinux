/* Copyright (C) 2017 Mellanox Technologies Inc. */

struct semanage_ibpkey;
struct semanage_ibpkey_key;
typedef struct semanage_ibpkey record_t;
typedef struct semanage_ibpkey_key record_key_t;
#define DBASE_RECORD_DEFINED

struct dbase_file;
typedef struct dbase_file dbase_t;
#define DBASE_DEFINED

#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <semanage/handle.h>
#include "ibpkey_internal.h"
#include "database_file.h"
#include "parse_utils.h"
#include "debug.h"

static int ibpkey_print(semanage_handle_t *handle,
			semanage_ibpkey_t *ibpkey, FILE *str)
{
	char *con_str = NULL;
	char *subnet_prefix_str = NULL;

	int low = semanage_ibpkey_get_low(ibpkey);
	int high = semanage_ibpkey_get_high(ibpkey);

	if (semanage_ibpkey_get_subnet_prefix(handle, ibpkey, &subnet_prefix_str) != 0)
		goto err;

	semanage_context_t *con = semanage_ibpkey_get_con(ibpkey);

	if (fprintf(str, "ibpkeycon %s ", subnet_prefix_str) < 0)
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

	free(subnet_prefix_str);
	free(con_str);
	return STATUS_SUCCESS;

err:
	ERR(handle, "could not print ibpkey range (%s) %u - %u to stream",
	    subnet_prefix_str, low, high);
	free(subnet_prefix_str);
	free(con_str);
	return STATUS_ERR;
}

static int ibpkey_parse(semanage_handle_t *handle,
			parse_info_t *info, semanage_ibpkey_t *ibpkey)
{
	int low, high;
	char *str = NULL;
	semanage_context_t *con = NULL;

	if (parse_skip_space(handle, info) < 0)
		goto err;
	if (!info->ptr)
		goto last;

	/* Header */
	if (parse_assert_str(handle, info, "ibpkeycon") < 0)
		goto err;
	if (parse_assert_space(handle, info) < 0)
		goto err;

	/* Subnet Prefix */
	if (parse_fetch_string(handle, info, &str, ' ') < 0)
		goto err;
	if (semanage_ibpkey_set_subnet_prefix(handle, ibpkey, str) < 0)
		goto err;
	free(str);
	str = NULL;

	/* Range/Pkey */
	if (parse_assert_space(handle, info) < 0)
		goto err;
	if (parse_fetch_int(handle, info, &low, '-') < 0)
		goto err;

	/* If range (-) does not follow immediately, require a space
	 * In other words, the space here is optional, but only
	 * in the ranged case, not in the single ibpkey case,
	 * so do a custom test
	 */
	if (*info->ptr && *info->ptr != '-') {
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
		semanage_ibpkey_set_range(ibpkey, low, high);
	} else {
		semanage_ibpkey_set_pkey(ibpkey, low);
	}
	/* Pkey context */
	if (parse_fetch_string(handle, info, &str, ' ') < 0)
		goto err;
	if (semanage_context_from_string(handle, str, &con) < 0) {
		ERR(handle, "invalid security context \"%s\" (%s: %u)\n%s",
		    str, info->filename, info->lineno, info->orig_line);
		goto err;
	}
	if (!con) {
		ERR(handle, "<<none>> context is not valid for ibpkeys (%s: %u):\n%s",
		    info->filename,
		    info->lineno, info->orig_line);
		goto err;
	}
	free(str);
	str = NULL;

	if (semanage_ibpkey_set_con(handle, ibpkey, con) < 0)
		goto err;

	if (parse_assert_space(handle, info) < 0)
		goto err;

	semanage_context_free(con);
	return STATUS_SUCCESS;

last:
	parse_dispose_line(info);
	return STATUS_NODATA;

err:
	ERR(handle, "could not parse ibpkey record");
	free(str);
	semanage_context_free(con);
	parse_dispose_line(info);
	return STATUS_ERR;
}

/* IBPKEY RECORD: FILE extension: method table */
record_file_table_t SEMANAGE_IBPKEY_FILE_RTABLE = {
	.parse = ibpkey_parse,
	.print = ibpkey_print,
};

int ibpkey_file_dbase_init(semanage_handle_t *handle,
			   const char *path_ro,
			   const char *path_rw,
			   dbase_config_t *dconfig)
{
	if (dbase_file_init(handle,
			    path_ro,
			    path_rw,
			    &SEMANAGE_IBPKEY_RTABLE,
			    &SEMANAGE_IBPKEY_FILE_RTABLE, &dconfig->dbase) < 0)
		return STATUS_ERR;

	dconfig->dtable = &SEMANAGE_FILE_DTABLE;
	return STATUS_SUCCESS;
}

void ibpkey_file_dbase_release(dbase_config_t *dconfig)
{
	dbase_file_release(dconfig->dbase);
}
