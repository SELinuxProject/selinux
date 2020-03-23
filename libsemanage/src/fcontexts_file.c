/* Copyright (C) 2005 Red Hat, Inc. */

struct semanage_fcontext;
struct semanage_fcontext_key;
typedef struct semanage_fcontext record_t;
typedef struct semanage_fcontext_key record_key_t;
#define DBASE_RECORD_DEFINED

struct dbase_file;
typedef struct dbase_file dbase_t;
#define DBASE_DEFINED

#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <semanage/handle.h>
#include "fcontext_internal.h"
#include "database_file.h"
#include "parse_utils.h"
#include "debug.h"

static const char *type_str(int type)
{
	switch (type) {
	default:
	case SEMANAGE_FCONTEXT_ALL:
		return "  ";
	case SEMANAGE_FCONTEXT_REG:
		return "--";
	case SEMANAGE_FCONTEXT_DIR:
		return "-d";
	case SEMANAGE_FCONTEXT_CHAR:
		return "-c";
	case SEMANAGE_FCONTEXT_BLOCK:
		return "-b";
	case SEMANAGE_FCONTEXT_SOCK:
		return "-s";
	case SEMANAGE_FCONTEXT_LINK:
		return "-l";
	case SEMANAGE_FCONTEXT_PIPE:
		return "-p";
	}
}

static int fcontext_print(semanage_handle_t * handle,
			  semanage_fcontext_t * fcontext, FILE * str)
{

	char *con_str = NULL;

	const char *expr = semanage_fcontext_get_expr(fcontext);
	int type = semanage_fcontext_get_type(fcontext);
	const char *print_str = type_str(type);
	const char *tstr = semanage_fcontext_get_type_str(type);
	semanage_context_t *con = semanage_fcontext_get_con(fcontext);

	if (fprintf(str, "%s %s ", expr, print_str) < 0)
		goto err;

	if (con != NULL) {
		if (semanage_context_to_string(handle, con, &con_str) < 0)
			goto err;
		if (fprintf(str, "%s\n", con_str) < 0)
			goto err;
		free(con_str);
		con_str = NULL;
	} else {
		if (fprintf(str, "<<none>>\n") < 0)
			goto err;
	}
	return STATUS_SUCCESS;

      err:
	ERR(handle, "could not print file context for "
	    "%s (%s) to stream", expr, tstr);
	free(con_str);
	return STATUS_ERR;
}

static int fcontext_parse(semanage_handle_t * handle,
			  parse_info_t * info, semanage_fcontext_t * fcontext)
{

	char *str = NULL;
	semanage_context_t *con = NULL;

	if (parse_skip_space(handle, info) < 0)
		goto err;
	if (!info->ptr)
		goto last;

	/* Regexp */
	if (parse_fetch_string(handle, info, &str, ' ') < 0)
		goto err;
	if (semanage_fcontext_set_expr(handle, fcontext, str) < 0)
		goto err;
	free(str);
	str = NULL;

	/* Type */
	if (parse_assert_space(handle, info) < 0)
		goto err;
	if (parse_fetch_string(handle, info, &str, ' ') < 0)
		goto err;
	if (!strcasecmp(str, "-s"))
		semanage_fcontext_set_type(fcontext, SEMANAGE_FCONTEXT_SOCK);
	else if (!strcasecmp(str, "-p"))
		semanage_fcontext_set_type(fcontext, SEMANAGE_FCONTEXT_PIPE);
	else if (!strcasecmp(str, "-b"))
		semanage_fcontext_set_type(fcontext, SEMANAGE_FCONTEXT_BLOCK);
	else if (!strcasecmp(str, "-l"))
		semanage_fcontext_set_type(fcontext, SEMANAGE_FCONTEXT_LINK);
	else if (!strcasecmp(str, "-c"))
		semanage_fcontext_set_type(fcontext, SEMANAGE_FCONTEXT_CHAR);
	else if (!strcasecmp(str, "-d"))
		semanage_fcontext_set_type(fcontext, SEMANAGE_FCONTEXT_DIR);
	else if (!strcasecmp(str, "--"))
		semanage_fcontext_set_type(fcontext, SEMANAGE_FCONTEXT_REG);
	else
		goto process_context;
	free(str);
	str = NULL;

	/* Context */
	if (parse_assert_space(handle, info) < 0)
		goto err;
	if (parse_fetch_string(handle, info, &str, ' ') < 0)
		goto err;

      process_context:
	if (semanage_context_from_string(handle, str, &con) < 0) {
		ERR(handle, "invalid security context \"%s\" (%s: %u)\n%s",
		    str, info->filename, info->lineno, info->orig_line);
		goto err;
	}
	free(str);
	str = NULL;

	if (con && semanage_fcontext_set_con(handle, fcontext, con) < 0)
		goto err;

	if (parse_assert_space(handle, info) < 0)
		goto err;

	semanage_context_free(con);
	return STATUS_SUCCESS;

      last:
	parse_dispose_line(info);
	return STATUS_NODATA;

      err:
	ERR(handle, "could not parse file context record");
	free(str);
	semanage_context_free(con);
	parse_dispose_line(info);
	return STATUS_ERR;
}

/* FCONTEXT RECORD: FILE extension: method table */
record_file_table_t SEMANAGE_FCONTEXT_FILE_RTABLE = {
	.parse = fcontext_parse,
	.print = fcontext_print,
};

int fcontext_file_dbase_init(semanage_handle_t * handle,
			     const char *path_ro,
			     const char *path_rw,
			     dbase_config_t * dconfig)
{

	if (dbase_file_init(handle,
			    path_ro,
			    path_rw,
			    &SEMANAGE_FCONTEXT_RTABLE,
			    &SEMANAGE_FCONTEXT_FILE_RTABLE,
			    &dconfig->dbase) < 0)
		return STATUS_ERR;

	dconfig->dtable = &SEMANAGE_FILE_DTABLE;
	return STATUS_SUCCESS;
}

void fcontext_file_dbase_release(dbase_config_t * dconfig)
{

	dbase_file_release(dconfig->dbase);
}
