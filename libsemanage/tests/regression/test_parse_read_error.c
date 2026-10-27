/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "handle.h"

static int read_calls;
static int injected_errno;
static int stream_error;
static int stream_eof;
static int give_record;

static ssize_t injected_getline(char **line, size_t *size, FILE *stream)
{
	(void)stream;
	read_calls++;
	if (give_record) {
		*line = strdup("record\n");
		assert(*line);
		*size = 8;
		give_record = 0;
		return 7;
	}
	errno = injected_errno;
	return -1;
}

#define getline injected_getline
#undef ferror
#undef feof
#define ferror(stream) ((void)(stream), stream_error)
#define feof(stream) ((void)(stream), stream_eof)
#include "../../src/parse_utils.c"
#undef getline

int main(void)
{
	semanage_handle_t sh = { 0 };
	parse_info_t info = { .filename = "local records",
			      .file_stream = stdin };
	int errors[] = { EIO, ENOMEM, 0, EIO };
	unsigned int i, after_record;
	int rc;

	for (after_record = 0; after_record < 2; after_record++) {
		for (i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
			give_record = after_record;
			if (give_record) {
				assert(parse_skip_space(&sh, &info) == 0);
				assert(strcmp(info.ptr, "record") == 0);
				info.ptr += strlen(info.ptr);
			}
			injected_errno = errors[i];
			stream_error = errors[i] == EIO;
			stream_eof = i >= 2;
			rc = parse_skip_space(&sh, &info);
			printf("getline errno=%d: parser rc=%d null_ptr=%d\n",
			       injected_errno, rc, info.ptr == NULL);
			assert(rc == (errors[i] ? -1 : 0) && info.ptr == NULL);
			if (errors[i])
				assert(errno == errors[i]);
		}
	}
	info.file_stream = NULL;
	i = read_calls;
	assert(parse_skip_space(&sh, &info) == 0);
	assert(read_calls == (int)i);
	puts("Parser read-error, EOF, and absent-file controls passed.");
	return 0;
}
