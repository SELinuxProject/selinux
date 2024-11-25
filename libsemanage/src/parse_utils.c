/* Copyright (C) 2005 Red Hat, Inc. */

#include <stdio.h>
#include <stdio_ext.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <semanage/handle.h>
#include "parse_utils.h"
#include "debug.h"

int parse_init(semanage_handle_t * handle,
	       const char *filename, void *parse_arg, parse_info_t ** info)
{

	parse_info_t *tmp_info = (parse_info_t *) malloc(sizeof(parse_info_t));

	if (!tmp_info) {
		ERR(handle,
		    "out of memory, could not allocate parse structure");
		return STATUS_ERR;
	}

	tmp_info->filename = filename;
	tmp_info->file_stream = NULL;
	tmp_info->working_copy = NULL;
	tmp_info->orig_line = NULL;
	tmp_info->ptr = NULL;
	tmp_info->lineno = 0;
	tmp_info->parse_arg = parse_arg;

	*info = tmp_info;
	return STATUS_SUCCESS;
}

void parse_release(parse_info_t * info)
{

	parse_close(info);
	parse_dispose_line(info);
	free(info);
}

int parse_open(semanage_handle_t * handle, parse_info_t * info)
{

	info->file_stream = fopen(info->filename, "re");
	if (!info->file_stream && (errno != ENOENT)) {
		ERR(handle, "could not open file %s.",
		    info->filename);
		return STATUS_ERR;
	}
	if (info->file_stream)
		__fsetlocking(info->file_stream, FSETLOCKING_BYCALLER);

	return STATUS_SUCCESS;
}

void parse_close(parse_info_t * info)
{

	if (info->file_stream)
		fclose(info->file_stream);
	info->file_stream = NULL;
}

void parse_dispose_line(parse_info_t * info)
{
	if (info->orig_line) {
		free(info->orig_line);
		info->orig_line = NULL;
	}

	if (info->working_copy) {
		free(info->working_copy);
		info->working_copy = NULL;
	}

	info->ptr = NULL;
}

int parse_skip_space(semanage_handle_t * handle, parse_info_t * info)
{

	size_t buf_len = 0;
	ssize_t len;
	unsigned int lineno = info->lineno;
	char *buffer = NULL;
	char *ptr;

	if (info->ptr) {
		while (*(info->ptr) && isspace((unsigned char)*(info->ptr)))
			info->ptr++;

		if (*(info->ptr))
			return STATUS_SUCCESS;
	}

	parse_dispose_line(info);

	while (info->file_stream &&
	       ((len = getline(&buffer, &buf_len, info->file_stream)) > 0)) {

		lineno++;

		/* Eat newline, preceding whitespace */
		if (buffer[len - 1] == '\n')
			buffer[len - 1] = '\0';

		ptr = buffer;
		while (*ptr && isspace((unsigned char)*ptr))
			ptr++;

		/* Skip comments and blank lines */
		if ((*ptr) && *ptr != '#') {
			char *tmp = strdup(buffer);
			if (!tmp)
				goto omem;

			info->lineno = lineno;
			info->working_copy = buffer;
			info->orig_line = tmp;
			info->ptr = ptr;

			return STATUS_SUCCESS;
		}
	}

	free(buffer);
	buffer = NULL;

	return STATUS_SUCCESS;

      omem:
	ERR(handle, "out of memory, could not allocate buffer");
	free(buffer);
	return STATUS_ERR;
}

int parse_assert_noeof(semanage_handle_t * handle, parse_info_t * info)
{

	if (!info->ptr) {
		ERR(handle, "unexpected end of file (%s: %u)",
		    info->filename, info->lineno);
		return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}

int parse_assert_space(semanage_handle_t * handle, parse_info_t * info)
{

	if (parse_assert_noeof(handle, info) < 0)
		return STATUS_ERR;

	if (*(info->ptr) && !isspace((unsigned char)*(info->ptr))) {
		ERR(handle, "missing whitespace (%s: %u):\n%s",
		    info->filename, info->lineno, info->orig_line);
		return STATUS_ERR;
	}

	if (parse_skip_space(handle, info) < 0)
		return STATUS_ERR;

	return STATUS_SUCCESS;
}

int parse_assert_ch(semanage_handle_t * handle,
		    parse_info_t * info, const char ch)
{

	if (parse_assert_noeof(handle, info) < 0)
		return STATUS_ERR;

	if (*(info->ptr) != ch) {
		ERR(handle, "expected character \'%c\', but found \'%c\' "
		    "(%s: %u):\n%s", ch, *(info->ptr), info->filename,
		    info->lineno, info->orig_line);
		return STATUS_ERR;
	}

	info->ptr++;

	return STATUS_SUCCESS;
}

int parse_assert_str(semanage_handle_t * handle,
		     parse_info_t * info, const char *assert_str)
{

	size_t len = strlen(assert_str);

	if (parse_assert_noeof(handle, info) < 0)
		return STATUS_ERR;

	if (strncmp(info->ptr, assert_str, len)) {
		ERR(handle, "experted string \"%s\", but found \"%s\" "
		    "(%s: %u):\n%s", assert_str, info->ptr,
		    info->filename, info->lineno, info->orig_line);

		return STATUS_ERR;
	}

	info->ptr += len;
	return STATUS_SUCCESS;
}

int parse_optional_ch(parse_info_t * info, const char ch)
{

	if (!info->ptr)
		return STATUS_NODATA;
	if (*(info->ptr) != ch)
		return STATUS_NODATA;

	info->ptr++;
	return STATUS_SUCCESS;
}

int parse_optional_str(parse_info_t * info, const char *str)
{
	size_t len = strlen(str);

	if (strncmp(info->ptr, str, len))
		return STATUS_NODATA;

	info->ptr += len;
	return STATUS_SUCCESS;
}

int parse_fetch_int(semanage_handle_t * handle,
		    parse_info_t * info, int *num, char delim)
{

	char *str = NULL;
	char *test = NULL;
	int value = 0;

	if (parse_fetch_string(handle, info, &str, delim, 0) < 0)
		goto err;

	if (!isdigit((unsigned char)*str)) {
		ERR(handle, "expected a numeric value: (%s: %u)\n%s",
		    info->filename, info->lineno, info->orig_line);
		goto err;
	}

	value = strtol(str, &test, 10);
	if (*test != '\0') {
		ERR(handle, "could not parse numeric value \"%s\": "
		    "(%s: %u)\n%s", str, info->filename,
		    info->lineno, info->orig_line);
		goto err;
	}

	*num = value;
	free(str);
	return STATUS_SUCCESS;

      err:
	ERR(handle, "could not fetch numeric value");
	free(str);
	return STATUS_ERR;
}

int parse_fetch_string(semanage_handle_t * handle,
		       parse_info_t * info, char **str, char delim, int allow_spaces)
{

	const char *start = info->ptr;
	size_t len = 0;
	char *tmp_str = NULL;

	if (parse_assert_noeof(handle, info) < 0)
		goto err;

	while (*(info->ptr) && (allow_spaces || !isspace((unsigned char)*(info->ptr))) &&
	       (*(info->ptr) != delim)) {
		info->ptr++;
		len++;
	}

	if (len == 0) {
		ERR(handle, "expected non-empty string, but did not "
		    "find one (%s: %u):\n%s", info->filename, info->lineno,
		    info->orig_line);
		goto err;
	}

	tmp_str = strndup(start, len);
	if (!tmp_str) {
		ERR(handle, "out of memory");
		goto err;
	}

	*str = tmp_str;
	return STATUS_SUCCESS;

      err:
	ERR(handle, "could not fetch string value");
	return STATUS_ERR;
}
