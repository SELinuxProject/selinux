/*
 * This file contains helper functions for labeling support.
 *
 * Author : Richard Haines <richard_c_haines@btinternet.com>
 */

#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>
#include "label_internal.h"

/*
 * The read_spec_entries and read_spec_entry functions may be used to
 * replace sscanf to read entries from spec files. The file and
 * property services now use these.
 */

/* Read an entry from a spec file (e.g. file_contexts) */
static inline int read_spec_entry(char **entry, char **ptr)
{
	int entry_len = 0;
	*entry = NULL;
	char *tmp_buf = NULL;

	while (isspace(**ptr) && **ptr != '\0')
		(*ptr)++;

	tmp_buf = *ptr;

	while (!isspace(**ptr) && **ptr != '\0') {
		(*ptr)++;
		entry_len++;
	}

	*entry = strndup(tmp_buf, entry_len);
	if (!*entry)
		return -1;

	return 0;
}

/*
 * line_buf - Buffer containing the spec entries .
 * num_args - The number of spec parameter entries to process.
 * ...      - A 'char **spec_entry' for each parameter.
 * returns  - The number of items processed.
 *
 * This function calls read_spec_entry() to do the actual string processing.
 */
int hidden read_spec_entries(char *line_buf, int num_args, ...)
{
	char **spec_entry, *buf_p;
	int len, rc, items;
	va_list ap;

	len = strlen(line_buf);
	if (line_buf[len - 1] == '\n')
		line_buf[len - 1] = '\0';

	buf_p = line_buf;
	while (isspace(*buf_p))
		buf_p++;

	/* Skip comment lines and empty lines. */
	if (*buf_p == '#' || *buf_p == '\0')
		return 0;

	/* Process the spec file entries */
	va_start(ap, num_args);

	for (items = 0; items < num_args; items++) {
		spec_entry = va_arg(ap, char **);

		if (len - 1 == buf_p - line_buf) {
			va_end(ap);
			return items;
		}

		rc = read_spec_entry(spec_entry, &buf_p);
		if (rc < 0) {
			va_end(ap);
			return rc;
		}
	}
	va_end(ap);
	return items;
}
