/*
 * File contexts backend for labeling system
 *
 * Author : Eamon Walsh <ewalsh@tycho.nsa.gov>
 * Author : Stephen Smalley <sds@tycho.nsa.gov>
 *
 * This library derived in part from setfiles and the setfiles.pl script
 * developed by Secure Computing Corporation.
 */

#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <pcre.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "callbacks.h"
#include "label_internal.h"
#include "label_file.h"

/*
 * Internals, mostly moved over from matchpathcon.c
 */

/* return the length of the text that is the stem of a file name */
static int get_stem_from_file_name(const char *const buf)
{
	const char *tmp = strchr(buf + 1, '/');

	if (!tmp)
		return 0;
	return tmp - buf;
}

/* find the stem of a file name, returns the index into stem_arr (or -1 if
 * there is no match - IE for a file in the root directory or a regex that is
 * too complex for us).  Makes buf point to the text AFTER the stem. */
static int find_stem_from_file(struct saved_data *data, const char **buf)
{
	int i;
	int stem_len = get_stem_from_file_name(*buf);

	if (!stem_len)
		return -1;
	for (i = 0; i < data->num_stems; i++) {
		if (stem_len == data->stem_arr[i].len
		    && !strncmp(*buf, data->stem_arr[i].buf, stem_len)) {
			*buf += stem_len;
			return i;
		}
	}
	return -1;
}

/*
 * Warn about duplicate specifications.
 */
static int nodups_specs(struct saved_data *data, const char *path)
{
	int rc = 0;
	unsigned int ii, jj;
	struct spec *curr_spec, *spec_arr = data->spec_arr;

	for (ii = 0; ii < data->nspec; ii++) {
		curr_spec = &spec_arr[ii];
		for (jj = ii + 1; jj < data->nspec; jj++) {
			if ((!strcmp(spec_arr[jj].regex_str, curr_spec->regex_str))
			    && (!spec_arr[jj].mode || !curr_spec->mode
				|| spec_arr[jj].mode == curr_spec->mode)) {
				rc = -1;
				errno = EINVAL;
				if (strcmp(spec_arr[jj].lr.ctx_raw, curr_spec->lr.ctx_raw)) {
					COMPAT_LOG
						(SELINUX_ERROR,
						 "%s: Multiple different specifications for %s  (%s and %s).\n",
						 path, curr_spec->regex_str,
						 spec_arr[jj].lr.ctx_raw,
						 curr_spec->lr.ctx_raw);
				} else {
					COMPAT_LOG
						(SELINUX_ERROR,
						 "%s: Multiple same specifications for %s.\n",
						 path, curr_spec->regex_str);
				}
			}
		}
	}
	return rc;
}

static int compile_regex(struct saved_data *data, struct spec *spec, const char **errbuf)
{
	const char *tmperrbuf;
	char *reg_buf, *anchored_regex, *cp;
	struct stem *stem_arr = data->stem_arr;
	size_t len;
	int erroff;

	if (spec->regcomp)
		return 0; /* already done */

	/* Skip the fixed stem. */
	reg_buf = spec->regex_str;
	if (spec->stem_id >= 0)
		reg_buf += stem_arr[spec->stem_id].len;

	/* Anchor the regular expression. */
	len = strlen(reg_buf);
	cp = anchored_regex = malloc(len + 3);
	if (!anchored_regex)
		return -1;

	/* Create ^...$ regexp.  */
	*cp++ = '^';
	cp = mempcpy(cp, reg_buf, len);
	*cp++ = '$';
	*cp = '\0';

	/* Compile the regular expression. */
	spec->regex = pcre_compile(anchored_regex, 0, &tmperrbuf, &erroff, NULL);
	free(anchored_regex);
	if (!spec->regex) {
		if (errbuf)
			*errbuf=tmperrbuf;
		return -1;
	}

	spec->sd = pcre_study(spec->regex, 0, &tmperrbuf);
	if (!spec->sd) {
		if (errbuf)
			*errbuf=tmperrbuf;
		return -1;
	}

	/* Done. */
	spec->regcomp = 1;

	return 0;
}

static int process_line(struct selabel_handle *rec,
			const char *path, const char *prefix,
			char *line_buf, int pass, unsigned lineno)
{
	int items, len;
	char *buf_p, *regex, *type, *context;
	struct saved_data *data = (struct saved_data *)rec->data;
	struct spec *spec_arr = data->spec_arr;
	unsigned int nspec = data->nspec;

	len = strlen(line_buf);
	if (line_buf[len - 1] == '\n')
		line_buf[len - 1] = 0;
	buf_p = line_buf;
	while (isspace(*buf_p))
		buf_p++;
	/* Skip comment lines and empty lines. */
	if (*buf_p == '#' || *buf_p == 0)
		return 0;
	items = sscanf(line_buf, "%as %as %as", &regex, &type, &context);
	if (items < 2) {
		COMPAT_LOG(SELINUX_WARNING,
			    "%s:  line %d is missing fields, skipping\n", path,
			    lineno);
		if (items == 1)
			free(regex);
		return 0;
	} else if (items == 2) {
		/* The type field is optional. */
		free(context);
		context = type;
		type = 0;
	}

	len = get_stem_from_spec(regex);
	if (len && prefix && strncmp(prefix, regex, len)) {
		/* Stem of regex does not match requested prefix, discard. */
		free(regex);
		free(type);
		free(context);
		return 0;
	}

	if (pass == 1) {
		/* On the second pass, process and store the specification in spec. */
		const char *errbuf = NULL;
		spec_arr[nspec].stem_id = find_stem_from_spec(data, regex);
		spec_arr[nspec].regex_str = regex;
		if (rec->validating && compile_regex(data, &spec_arr[nspec], &errbuf)) {
			COMPAT_LOG(SELINUX_WARNING,
				   "%s:  line %d has invalid regex %s:  %s\n",
				   path, lineno, regex,
				   (errbuf ? errbuf : "out of memory"));
		}

		/* Convert the type string to a mode format */
		spec_arr[nspec].type_str = type;
		spec_arr[nspec].mode = 0;
		if (type) {
			mode_t mode = string_to_mode(type);
			if (mode == -1) {
				COMPAT_LOG(SELINUX_WARNING,
					"%s:  line %d has invalid file type %s\n",
					path, lineno, type);
				mode = 0;
			}
			spec_arr[nspec].mode = mode;
		}

		spec_arr[nspec].lr.ctx_raw = context;

		/* Determine if specification has 
		 * any meta characters in the RE */
		spec_hasMetaChars(&spec_arr[nspec]);

		if (strcmp(context, "<<none>>") && rec->validating)
			compat_validate(rec, &spec_arr[nspec].lr, path, lineno);
	}

	data->nspec = ++nspec;
	if (pass == 0) {
		free(regex);
		if (type)
			free(type);
		free(context);
	}
	return 0;
}

static int init(struct selabel_handle *rec, struct selinux_opt *opts,
		unsigned n)
{
	struct saved_data *data = (struct saved_data *)rec->data;
	const char *path = NULL;
	const char *prefix = NULL;
	FILE *fp;
	FILE *localfp = NULL;
	FILE *homedirfp = NULL;
	char local_path[PATH_MAX + 1];
	char homedir_path[PATH_MAX + 1];
	char subs_file[PATH_MAX + 1];
	char *line_buf = NULL;
	size_t line_len = 0;
	unsigned int lineno, pass, maxnspec;
	int status = -1, baseonly = 0;
	struct stat sb;

	/* Process arguments */
	while (n--)
		switch(opts[n].type) {
		case SELABEL_OPT_PATH:
			path = opts[n].value;
			break;
		case SELABEL_OPT_SUBSET:
			prefix = opts[n].value;
			break;
		case SELABEL_OPT_BASEONLY:
			baseonly = !!opts[n].value;
			break;
		}

	/* Process local and distribution substitution files */
	if (!path) {
		rec->subs = selabel_subs_init(selinux_file_context_subs_dist_path(), rec->subs);
		rec->subs = selabel_subs_init(selinux_file_context_subs_path(), rec->subs);
	} else {
		snprintf(subs_file, sizeof(subs_file), "%s.subs_dist", path);
		rec->subs = selabel_subs_init(subs_file, rec->subs);
		snprintf(subs_file, sizeof(subs_file), "%s.subs", path);
		rec->subs = selabel_subs_init(subs_file, rec->subs);
	}

	/* Open the specification file. */
	if (!path)
		path = selinux_file_context_path();
	if ((fp = fopen(path, "r")) == NULL)
		return -1;
	__fsetlocking(fp, FSETLOCKING_BYCALLER);

	if (fstat(fileno(fp), &sb) < 0)
		return -1;
	if (!S_ISREG(sb.st_mode)) {
		errno = EINVAL;
		return -1;
	}

	if (!baseonly) {
		snprintf(homedir_path, sizeof(homedir_path), "%s.homedirs",
			 path);
		homedirfp = fopen(homedir_path, "r");
		if (homedirfp != NULL)
			__fsetlocking(homedirfp, FSETLOCKING_BYCALLER);

		snprintf(local_path, sizeof(local_path), "%s.local", path);
		localfp = fopen(local_path, "r");
		if (localfp != NULL)
			__fsetlocking(localfp, FSETLOCKING_BYCALLER);
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
	maxnspec = UINT_MAX / sizeof(struct spec);
	for (pass = 0; pass < 2; pass++) {
		data->nspec = 0;

		lineno = 0;
		while (getline(&line_buf, &line_len, fp) > 0) {
			if (data->nspec >= maxnspec)
				break;
			status = process_line(rec, path, prefix, line_buf, pass, ++lineno);
			if (status)
				goto finish;
		}

		if (pass == 1 && rec->validating) {
			status = nodups_specs(data, path);
			if (status)
				goto finish;
		}

		lineno = 0;
		if (homedirfp)
			while (getline(&line_buf, &line_len, homedirfp) > 0) {
				if (data->nspec >= maxnspec)
					break;
				status = process_line(rec, homedir_path, prefix, line_buf, pass, ++lineno);
				if (status)
					goto finish;
			}

		lineno = 0;
		if (localfp)
			while (getline(&line_buf, &line_len, localfp) > 0) {
				if (data->nspec >= maxnspec)
					break;
				status = process_line(rec, local_path, prefix, line_buf, pass, ++lineno);
				if (status)
					goto finish;
			}

		if (pass == 0) {
			if (data->nspec == 0) {
				status = 0;
				goto finish;
			}
			data->spec_arr = calloc(data->nspec, sizeof(*data->spec_arr));
			if (!data->spec_arr)
				goto finish;

			maxnspec = data->nspec;
			rewind(fp);
			if (homedirfp)
				rewind(homedirfp);
			if (localfp)
				rewind(localfp);
		}
	}
	free(line_buf);

	status = sort_specs(data);

	status = 0;
finish:
	fclose(fp);
	if (status)
		free(data->spec_arr);
	if (homedirfp)
		fclose(homedirfp);
	if (localfp)
		fclose(localfp);
	return status;
}

/*
 * Backend interface routines
 */
static void closef(struct selabel_handle *rec)
{
	struct saved_data *data = (struct saved_data *)rec->data;
	struct spec *spec;
	struct stem *stem;
	unsigned int i;

	for (i = 0; i < data->nspec; i++) {
		spec = &data->spec_arr[i];
		free(spec->regex_str);
		free(spec->type_str);
		free(spec->lr.ctx_raw);
		free(spec->lr.ctx_trans);
		if (spec->regcomp) {
			pcre_free(spec->regex);
			pcre_free_study(spec->sd);
		}
	}

	for (i = 0; i < (unsigned int)data->num_stems; i++) {
		stem = &data->stem_arr[i];
		free(stem->buf);
	}

	if (data->spec_arr)
		free(data->spec_arr);
	if (data->stem_arr)
		free(data->stem_arr);
	
	free(data);
}

static struct selabel_lookup_rec *lookup(struct selabel_handle *rec,
					 const char *key, int type)
{
	struct saved_data *data = (struct saved_data *)rec->data;
	struct spec *spec_arr = data->spec_arr;
	int i, rc, file_stem;
	mode_t mode = (mode_t)type;
	const char *buf;
	struct selabel_lookup_rec *ret = NULL;
	char *clean_key = NULL;
	const char *prev_slash, *next_slash;
	unsigned int sofar = 0;

	if (!data->nspec) {
		errno = ENOENT;
		goto finish;
	}

	/* Remove duplicate slashes */
	if ((next_slash = strstr(key, "//"))) {
		clean_key = malloc(strlen(key) + 1);
		if (!clean_key)
			goto finish;
		prev_slash = key;
		while (next_slash) {
			memcpy(clean_key + sofar, prev_slash, next_slash - prev_slash);
			sofar += next_slash - prev_slash;
			prev_slash = next_slash + 1;
			next_slash = strstr(prev_slash, "//");
		}
		strcpy(clean_key + sofar, prev_slash);
		key = clean_key;
	}

	buf = key;
	file_stem = find_stem_from_file(data, &buf);
	mode &= S_IFMT;

	/* 
	 * Check for matching specifications in reverse order, so that
	 * the last matching specification is used.
	 */
	for (i = data->nspec - 1; i >= 0; i--) {
		struct spec *spec = &spec_arr[i];
		/* if the spec in question matches no stem or has the same
		 * stem as the file AND if the spec in question has no mode
		 * specified or if the mode matches the file mode then we do
		 * a regex check        */
		if ((spec->stem_id == -1 || spec->stem_id == file_stem) &&
		    (!mode || !spec->mode || mode == spec->mode)) {
			if (compile_regex(data, spec, NULL) < 0)
				goto finish;
			if (spec->stem_id == -1)
				rc = pcre_exec(spec->regex, get_pcre_extra(spec), key, strlen(key), 0, 0, NULL, 0);
			else
				rc = pcre_exec(spec->regex, get_pcre_extra(spec), buf, strlen(buf), 0, 0, NULL, 0);

			if (rc == 0) {
				spec->matches++;
				break;
			} else if (rc == PCRE_ERROR_NOMATCH)
				continue;
			/* else it's an error */
			goto finish;
		}
	}

	if (i < 0 || strcmp(spec_arr[i].lr.ctx_raw, "<<none>>") == 0) {
		/* No matching specification. */
		errno = ENOENT;
		goto finish;
	}

	ret = &spec_arr[i].lr;

finish:
	free(clean_key);
	return ret;
}

static void stats(struct selabel_handle *rec)
{
	struct saved_data *data = (struct saved_data *)rec->data;
	unsigned int i, nspec = data->nspec;
	struct spec *spec_arr = data->spec_arr;

	for (i = 0; i < nspec; i++) {
		if (spec_arr[i].matches == 0) {
			if (spec_arr[i].type_str) {
				COMPAT_LOG(SELINUX_WARNING,
				    "Warning!  No matches for (%s, %s, %s)\n",
				    spec_arr[i].regex_str,
				    spec_arr[i].type_str,
				    spec_arr[i].lr.ctx_raw);
			} else {
				COMPAT_LOG(SELINUX_WARNING,
				    "Warning!  No matches for (%s, %s)\n",
				    spec_arr[i].regex_str,
				    spec_arr[i].lr.ctx_raw);
			}
		}
	}
}

int selabel_file_init(struct selabel_handle *rec, struct selinux_opt *opts,
		      unsigned nopts)
{
	struct saved_data *data;

	data = (struct saved_data *)malloc(sizeof(*data));
	if (!data)
		return -1;
	memset(data, 0, sizeof(*data));

	rec->data = data;
	rec->func_close = &closef;
	rec->func_stats = &stats;
	rec->func_lookup = &lookup;

	return init(rec, opts, nopts);
}
