/*
 * This file contains helper functions for labeling support.
 *
 * Author : Richard Haines <richard_c_haines@btinternet.com>
 */

#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "label_internal.h"

/*
 * The read_spec_entries and read_spec_entry functions may be used to
 * replace sscanf to read entries from spec files. The file and
 * property services now use these.
 */
static inline int read_spec_entry(char **entry, char **ptr, int *len)
{
	*entry = NULL;
	char *tmp_buf = NULL;

	while (isspace(**ptr) && **ptr != '\0')
		(*ptr)++;

	tmp_buf = *ptr;
	*len = 0;

	while (!isspace(**ptr) && **ptr != '\0') {
		(*ptr)++;
		(*len)++;
	}

	if (*len) {
		*entry = strndup(tmp_buf, *len);
		if (!*entry)
			return -1;
	}

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
	int len, rc, items, entry_len = 0;
	va_list ap;

	len = strlen(line_buf);
	if (line_buf[len - 1] == '\n')
		line_buf[len - 1] = '\0';
	else
		/* Handle case if line not \n terminated by bumping
		 * the len for the check below (as the line is NUL
		 * terminated by getline(3)) */
		len++;

	buf_p = line_buf;
	while (isspace(*buf_p))
		buf_p++;

	/* Skip comment lines and empty lines. */
	if (*buf_p == '#' || *buf_p == '\0')
		return 0;

	/* Process the spec file entries */
	va_start(ap, num_args);

	items = 0;
	while (items < num_args) {
		spec_entry = va_arg(ap, char **);

		if (len - 1 == buf_p - line_buf) {
			va_end(ap);
			return items;
		}

		rc = read_spec_entry(spec_entry, &buf_p, &entry_len);
		if (rc < 0) {
			va_end(ap);
			return rc;
		}
		if (entry_len)
			items++;
	}
	va_end(ap);
	return items;
}

/* Once all the specfiles are in the hash_buf, generate the hash. */
void hidden digest_gen_hash(struct selabel_digest *digest)
{
	Sha1Context context;

	/* If SELABEL_OPT_DIGEST not set then just return */
	if (!digest)
		return;

	Sha1Initialise(&context);
	Sha1Update(&context, digest->hashbuf, digest->hashbuf_size);
	Sha1Finalise(&context, (SHA1_HASH *)digest->digest);
	free(digest->hashbuf);
	digest->hashbuf = NULL;
	return;
}

/**
 * digest_add_specfile - Add a specfile to the hashbuf and if gen_hash true
 *			 then generate the hash.
 * @digest: pointer to the selabel_digest struct
 * @fp: file pointer for fread(3) or NULL if not.
 * @from_addr: pointer at start of buffer for memcpy or NULL if not (used for
 *	       mmap(3) files).
 * @buf_len: length of buffer to copy.
 * @path: pointer to the specfile.
 *
 * Return %0 on success, -%1 with @errno set on failure.
 */
int hidden digest_add_specfile(struct selabel_digest *digest, FILE *fp,
				    char *from_addr, size_t buf_len,
				    const char *path)
{
	unsigned char *tmp_buf;

	/* If SELABEL_OPT_DIGEST not set then just return */
	if (!digest)
		return 0;

	if (digest->hashbuf_size + buf_len < digest->hashbuf_size) {
		errno = EOVERFLOW;
		return -1;
	}
	digest->hashbuf_size += buf_len;

	tmp_buf = realloc(digest->hashbuf, digest->hashbuf_size);
	if (!tmp_buf)
		return -1;

	digest->hashbuf = tmp_buf;

	if (fp) {
		rewind(fp);
		if (fread(digest->hashbuf + (digest->hashbuf_size - buf_len),
					    1, buf_len, fp) != buf_len)
			return -1;

		rewind(fp);
	} else if (from_addr) {
		tmp_buf = memcpy(digest->hashbuf +
				    (digest->hashbuf_size - buf_len),
				    from_addr, buf_len);
		if (!tmp_buf)
			return -1;
	}
	/* Now add path to list */
	digest->specfile_list[digest->specfile_cnt] = strdup(path);
	if (!digest->specfile_list[digest->specfile_cnt])
		return -1;

	digest->specfile_cnt++;
	if (digest->specfile_cnt > DIGEST_FILES_MAX) {
		errno = EOVERFLOW;
		return -1;
	}

	return 0;
}
