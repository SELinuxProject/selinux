/*
 * Media contexts backend for X contexts
 *
 * Author : Eamon Walsh <ewalsh@tycho.nsa.gov>
 */

#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <fnmatch.h>
#include "callbacks.h"
#include "label_internal.h"

/*
 * Internals
 */

/* A context specification. */
typedef struct spec {
	struct selabel_lookup_rec lr;	/* holds contexts for lookup result */
	char *key;		/* key string */
	int type;		/* type of record (prop, ext, client) */
	int matches;		/* number of matches made during operation */
} spec_t;

struct saved_data {
	unsigned int nspec;
	spec_t *spec_arr;
};

static int process_line(const char *path, char *line_buf, int pass,
			unsigned lineno, struct selabel_handle *rec)
{
	struct saved_data *data = (struct saved_data *)rec->data;
	int items;
	char *buf_p;
	char *type, *key, *context;

	buf_p = line_buf;
	while (isspace(*buf_p))
		buf_p++;
	/* Skip comment lines and empty lines. */
	if (*buf_p == '#' || *buf_p == 0)
		return 0;
	items = sscanf(line_buf, "%ms %ms %ms ", &type, &key, &context);
	if (items < 3) {
		selinux_log(SELINUX_WARNING,
			    "%s:  line %u is missing fields, skipping\n", path,
			    lineno);
		if (items > 0)
			free(type);
		if (items > 1)
			free(key);
		return 0;
	}

	if (pass == 1) {
		/* Convert the type string to a mode format */
		if (!strcmp(type, "property"))
			data->spec_arr[data->nspec].type = SELABEL_X_PROP;
		else if (!strcmp(type, "extension"))
			data->spec_arr[data->nspec].type = SELABEL_X_EXT;
		else if (!strcmp(type, "client"))
			data->spec_arr[data->nspec].type = SELABEL_X_CLIENT;
		else if (!strcmp(type, "event"))
			data->spec_arr[data->nspec].type = SELABEL_X_EVENT;
		else if (!strcmp(type, "selection"))
			data->spec_arr[data->nspec].type = SELABEL_X_SELN;
		else if (!strcmp(type, "poly_property"))
			data->spec_arr[data->nspec].type = SELABEL_X_POLYPROP;
		else if (!strcmp(type, "poly_selection"))
			data->spec_arr[data->nspec].type = SELABEL_X_POLYSELN;
		else {
			selinux_log(SELINUX_WARNING,
				    "%s:  line %u has invalid object type %s\n",
				    path, lineno, type);
			return 0;
		}
		data->spec_arr[data->nspec].key = key;
		data->spec_arr[data->nspec].lr.ctx_raw = context;
		free(type);
	}

	data->nspec++;
	if (pass == 0) {
		free(type);
		free(key);
		free(context);
	}
	return 0;
}

static int init(struct selabel_handle *rec, const struct selinux_opt *opts,
		unsigned n)
{
	FILE *fp;
	struct saved_data *data = (struct saved_data *)rec->data;
	const char *path = NULL;
	char *line_buf = NULL;
	size_t line_len = 0;
	int status = -1;
	unsigned int lineno, pass, maxnspec;
	struct stat sb;

	/* Process arguments */
	while (n--)
		switch(opts[n].type) {
		case SELABEL_OPT_PATH:
			path = opts[n].value;
			break;
		}

	/* Open the specification file. */
	if (!path)
		path = selinux_x_context_path();
	if ((fp = fopen(path, "re")) == NULL)
		return -1;
	__fsetlocking(fp, FSETLOCKING_BYCALLER);

	if (fstat(fileno(fp), &sb) < 0)
		return -1;
	if (!S_ISREG(sb.st_mode)) {
		errno = EINVAL;
		return -1;
	}
	rec->spec_file = strdup(path);

	/* 
	 * Perform two passes over the specification file.
	 * The first pass counts the number of specifications and
	 * performs simple validation of the input.  At the end
	 * of the first pass, the spec array is allocated.
	 * The second pass performs detailed validation of the input
	 * and fills in the spec array.
	 */
	maxnspec = UINT_MAX / sizeof(spec_t);
	for (pass = 0; pass < 2; pass++) {
		lineno = 0;
		data->nspec = 0;
		while (getline(&line_buf, &line_len, fp) > 0 &&
		       data->nspec < maxnspec) {
			if (process_line(path, line_buf, pass, ++lineno, rec))
				goto finish;
		}
		lineno = 0;

		if (pass == 0) {
			if (data->nspec == 0) {
				status = 0;
				goto finish;
			}
			data->spec_arr = malloc(sizeof(spec_t)*data->nspec);
			if (data->spec_arr == NULL)
				goto finish;
			memset(data->spec_arr, 0, sizeof(spec_t)*data->nspec);
			maxnspec = data->nspec;
			rewind(fp);
		}
	}
	free(line_buf);

	status = digest_add_specfile(rec->digest, fp, NULL, sb.st_size, path);
	if (status)
		goto finish;

	digest_gen_hash(rec->digest);

finish:
	fclose(fp);
	return status;
}

/*
 * Backend interface routines
 */
static void close(struct selabel_handle *rec)
{
	struct saved_data *data = (struct saved_data *)rec->data;
	struct spec *spec, *spec_arr = data->spec_arr;
	unsigned int i;

	for (i = 0; i < data->nspec; i++) {
		spec = &spec_arr[i];
		free(spec->key);
		free(spec->lr.ctx_raw);
		free(spec->lr.ctx_trans);
	}

	if (spec_arr)
	    free(spec_arr);

	free(data);
}

static struct selabel_lookup_rec *lookup(struct selabel_handle *rec,
					 const char *key, int type)
{
	struct saved_data *data = (struct saved_data *)rec->data;
	spec_t *spec_arr = data->spec_arr;
	unsigned int i;

	for (i = 0; i < data->nspec; i++) {
		if (spec_arr[i].type != type)
			continue;
		if (!fnmatch(spec_arr[i].key, key, 0))
			break;
	}

	if (i >= data->nspec) {
		/* No matching specification. */
		errno = ENOENT;
		return NULL;
	}

	spec_arr[i].matches++;
	return &spec_arr[i].lr;
}

static void stats(struct selabel_handle *rec)
{
	struct saved_data *data = (struct saved_data *)rec->data;
	unsigned int i, total = 0;

	for (i = 0; i < data->nspec; i++)
		total += data->spec_arr[i].matches;

	selinux_log(SELINUX_INFO, "%u entries, %u matches made\n",
		  data->nspec, total);
}

int selabel_x_init(struct selabel_handle *rec, const struct selinux_opt *opts,
		   unsigned nopts)
{
	struct saved_data *data;

	data = (struct saved_data *)malloc(sizeof(*data));
	if (!data)
		return -1;
	memset(data, 0, sizeof(*data));

	rec->data = data;
	rec->func_close = &close;
	rec->func_lookup = &lookup;
	rec->func_stats = &stats;

	return init(rec, opts, nopts);
}
