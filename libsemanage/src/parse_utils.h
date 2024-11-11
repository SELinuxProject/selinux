/* Copyright (C) 2005 Red Hat, Inc. */

#ifndef _SEMANAGE_PARSE_UTILS_INTERNAL_H_
#define _SEMANAGE_PARSE_UTILS_INTERNAL_H_

#include <stdio.h>
#include <semanage/handle.h>

typedef struct parse_info {
	unsigned int lineno;	/* Current line number */
	char *orig_line;	/* Original copy of the line being parsed */
	char *working_copy;	/* Working copy of the line being parsed */
	char *ptr;		/* Current parsing location */

	const char *filename;	/* Input stream file name */
	FILE *file_stream;	/* Input stream handle */

	void *parse_arg;	/* Caller supplied argument */
} parse_info_t;

/* Initialize structure */
extern int parse_init(semanage_handle_t * handle,
		      const char *filename,
		      void *parse_arg, parse_info_t ** info);

/* Release structure */
extern void parse_release(parse_info_t * info);

/* Open file */
extern int parse_open(semanage_handle_t * handle, parse_info_t * info);

/* Close file */
extern void parse_close(parse_info_t * info);

/* Release resources for current line */
extern void parse_dispose_line(parse_info_t * info);

/* Skip all whitespace and comments */
extern int parse_skip_space(semanage_handle_t * handle, parse_info_t * info);

/* Throw an error if we're at the EOF */
extern int parse_assert_noeof(semanage_handle_t * handle, parse_info_t * info);

/* Throw an error if no whitespace follows,
 * otherwise eat the whitespace */
extern int parse_assert_space(semanage_handle_t * handle, parse_info_t * info);

/* Throw an error if the specified character
 * does not follow, otherwise eat that character */
extern int parse_assert_ch(semanage_handle_t * handle,
			   parse_info_t * info, char ch);

/* Throw an error if the specified string
 * does not follow is not found, otherwise
 * eat the string */
extern int parse_assert_str(semanage_handle_t * handle,
			    parse_info_t * info, const char *assert_str);

/* Eat the optional character, if found,
 * or return STATUS_NODATA */
extern int parse_optional_ch(parse_info_t * info, char ch);

/* Eat the optional string, if found,
 * or return STATUS_NODATA */
extern int parse_optional_str(parse_info_t * info, const char *str);

/* Extract the next integer, and move
 * the read pointer past it. Stop if
 * the optional character delim is encountered,
 * or if whitespace/eof is encountered */
int parse_fetch_int(semanage_handle_t * hgandle,
		    parse_info_t * info, int *num, char delim);

/* Extract the next string and move the read pointer past it.
 * Stop if the optional character delim (or eof) is encountered,
 * or if whitespace is encountered and allow_spaces is 0.
 * Fail if the string is of length 0. */
extern int parse_fetch_string(semanage_handle_t * handle,
			      parse_info_t * info, char **str_ptr, char delim, int allow_spaces);

#endif
