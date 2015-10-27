/*
 * File contexts backend for labeling system
 *
 * Author : Eamon Walsh <ewalsh@tycho.nsa.gov>
 * Author : Stephen Smalley <sds@tycho.nsa.gov>
 */

#include <assert.h>
#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <pcre.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

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
			if ((!strcmp(spec_arr[jj].regex_str,
				curr_spec->regex_str))
			    && (!spec_arr[jj].mode || !curr_spec->mode
				|| spec_arr[jj].mode == curr_spec->mode)) {
				rc = -1;
				errno = EINVAL;
				if (strcmp(spec_arr[jj].lr.ctx_raw,
					    curr_spec->lr.ctx_raw)) {
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

static int load_mmap(struct selabel_handle *rec, const char *path,
				    struct stat *sb, bool isbinary,
				    struct selabel_digest *digest)
{
	struct saved_data *data = (struct saved_data *)rec->data;
	char mmap_path[PATH_MAX + 1];
	int mmapfd;
	int rc;
	struct stat mmap_stat;
	char *addr, *str_buf;
	size_t len;
	int *stem_map;
	struct mmap_area *mmap_area;
	uint32_t i, magic, version;
	uint32_t entry_len, stem_map_len, regex_array_len;

	if (isbinary) {
		len = strlen(path);
		if (len >= sizeof(mmap_path))
			return -1;
		strcpy(mmap_path, path);
	} else {
		rc = snprintf(mmap_path, sizeof(mmap_path), "%s.bin", path);
		if (rc >= (int)sizeof(mmap_path))
			return -1;
	}

	mmapfd = open(mmap_path, O_RDONLY | O_CLOEXEC);
	if (mmapfd < 0)
		return -1;

	rc = fstat(mmapfd, &mmap_stat);
	if (rc < 0) {
		close(mmapfd);
		return -1;
	}

	/* if mmap is old, ignore it */
	if (mmap_stat.st_mtime < sb->st_mtime) {
		close(mmapfd);
		return -1;
	}

	/* ok, read it in... */
	len = mmap_stat.st_size;
	len += (sysconf(_SC_PAGE_SIZE) - 1);
	len &= ~(sysconf(_SC_PAGE_SIZE) - 1);

	mmap_area = malloc(sizeof(*mmap_area));
	if (!mmap_area) {
		close(mmapfd);
		return -1;
	}

	addr = mmap(NULL, len, PROT_READ, MAP_PRIVATE, mmapfd, 0);
	close(mmapfd);
	if (addr == MAP_FAILED) {
		free(mmap_area);
		perror("mmap");
		return -1;
	}

	/* save where we mmap'd the file to cleanup on close() */
	mmap_area->addr = mmap_area->next_addr = addr;
	mmap_area->len = mmap_area->next_len = len;
	mmap_area->next = data->mmap_areas;
	data->mmap_areas = mmap_area;

	/* check if this looks like an fcontext file */
	rc = next_entry(&magic, mmap_area, sizeof(uint32_t));
	if (rc < 0 || magic != SELINUX_MAGIC_COMPILED_FCONTEXT)
		return -1;

	/* check if this version is higher than we understand */
	rc = next_entry(&version, mmap_area, sizeof(uint32_t));
	if (rc < 0 || version > SELINUX_COMPILED_FCONTEXT_MAX_VERS)
		return -1;

	if (version >= SELINUX_COMPILED_FCONTEXT_PCRE_VERS) {
		len = strlen(pcre_version());

		rc = next_entry(&entry_len, mmap_area, sizeof(uint32_t));
		if (rc < 0)
			return -1;

		/* Check version lengths */
		if (len != entry_len)
			return -1;

		/* Check if pcre version mismatch */
		str_buf = malloc(entry_len + 1);
		if (!str_buf)
			return -1;

		rc = next_entry(str_buf, mmap_area, entry_len);
		if (rc < 0) {
			free(str_buf);
			return -1;
		}

		str_buf[entry_len] = '\0';
		if ((strcmp(str_buf, pcre_version()) != 0)) {
			free(str_buf);
			return -1;
		}
		free(str_buf);
	}

	/* allocate the stems_data array */
	rc = next_entry(&stem_map_len, mmap_area, sizeof(uint32_t));
	if (rc < 0 || !stem_map_len)
		return -1;

	/*
	 * map indexed by the stem # in the mmap file and contains the stem
	 * number in the data stem_arr
	 */
	stem_map = calloc(stem_map_len, sizeof(*stem_map));
	if (!stem_map)
		return -1;

	for (i = 0; i < stem_map_len; i++) {
		char *buf;
		uint32_t stem_len;
		int newid;

		/* the length does not inlude the nul */
		rc = next_entry(&stem_len, mmap_area, sizeof(uint32_t));
		if (rc < 0 || !stem_len) {
			rc = -1;
			goto err;
		}

		/* Check for stem_len wrap around. */
		if (stem_len < UINT32_MAX) {
			buf = (char *)mmap_area->next_addr;
			/* Check if over-run before null check. */
			rc = next_entry(NULL, mmap_area, (stem_len + 1));
			if (rc < 0)
				goto err;

			if (buf[stem_len] != '\0') {
				rc = -1;
				goto err;
			}
		} else {
			rc = -1;
			goto err;
		}

		/* store the mapping between old and new */
		newid = find_stem(data, buf, stem_len);
		if (newid < 0) {
			newid = store_stem(data, buf, stem_len);
			if (newid < 0) {
				rc = newid;
				goto err;
			}
			data->stem_arr[newid].from_mmap = 1;
		}
		stem_map[i] = newid;
	}

	/* allocate the regex array */
	rc = next_entry(&regex_array_len, mmap_area, sizeof(uint32_t));
	if (rc < 0 || !regex_array_len) {
		rc = -1;
		goto err;
	}

	for (i = 0; i < regex_array_len; i++) {
		struct spec *spec;
		int32_t stem_id, meta_chars;
		uint32_t mode = 0, prefix_len = 0;

		rc = grow_specs(data);
		if (rc < 0)
			goto err;

		spec = &data->spec_arr[data->nspec];
		spec->from_mmap = 1;
		spec->regcomp = 1;

		/* Process context */
		rc = next_entry(&entry_len, mmap_area, sizeof(uint32_t));
		if (rc < 0 || !entry_len) {
			rc = -1;
			goto err;
		}

		str_buf = malloc(entry_len);
		if (!str_buf) {
			rc = -1;
			goto err;
		}
		rc = next_entry(str_buf, mmap_area, entry_len);
		if (rc < 0)
			goto err;

		if (str_buf[entry_len - 1] != '\0') {
			free(str_buf);
			rc = -1;
			goto err;
		}
		spec->lr.ctx_raw = str_buf;

		if (strcmp(spec->lr.ctx_raw, "<<none>>") && rec->validating) {
			if (selabel_validate(rec, &spec->lr) < 0) {
				selinux_log(SELINUX_ERROR,
					    "%s: context %s is invalid\n", mmap_path, spec->lr.ctx_raw);
				goto err;
			}
		}

		/* Process regex string */
		rc = next_entry(&entry_len, mmap_area, sizeof(uint32_t));
		if (rc < 0 || !entry_len) {
			rc = -1;
			goto err;
		}

		spec->regex_str = (char *)mmap_area->next_addr;
		rc = next_entry(NULL, mmap_area, entry_len);
		if (rc < 0)
			goto err;

		if (spec->regex_str[entry_len - 1] != '\0') {
			rc = -1;
			goto err;
		}

		/* Process mode */
		if (version >= SELINUX_COMPILED_FCONTEXT_MODE)
			rc = next_entry(&mode, mmap_area, sizeof(uint32_t));
		else
			rc = next_entry(&mode, mmap_area, sizeof(mode_t));
		if (rc < 0)
			goto err;

		spec->mode = mode;

		/* map the stem id from the mmap file to the data->stem_arr */
		rc = next_entry(&stem_id, mmap_area, sizeof(int32_t));
		if (rc < 0)
			goto err;

		if (stem_id < 0 || stem_id >= (int32_t)stem_map_len)
			spec->stem_id = -1;
		 else
			spec->stem_id = stem_map[stem_id];

		/* retrieve the hasMetaChars bit */
		rc = next_entry(&meta_chars, mmap_area, sizeof(uint32_t));
		if (rc < 0)
			goto err;

		spec->hasMetaChars = meta_chars;
		/* and prefix length for use by selabel_lookup_best_match */
		if (version >= SELINUX_COMPILED_FCONTEXT_PREFIX_LEN) {
			rc = next_entry(&prefix_len, mmap_area,
					    sizeof(uint32_t));
			if (rc < 0)
				goto err;

			spec->prefix_len = prefix_len;
		}

		/* Process regex and study_data entries */
		rc = next_entry(&entry_len, mmap_area, sizeof(uint32_t));
		if (rc < 0 || !entry_len) {
			rc = -1;
			goto err;
		}
		spec->regex = (pcre *)mmap_area->next_addr;
		rc = next_entry(NULL, mmap_area, entry_len);
		if (rc < 0)
			goto err;

		/* Check that regex lengths match. pcre_fullinfo()
		 * also validates its magic number. */
		rc = pcre_fullinfo(spec->regex, NULL, PCRE_INFO_SIZE, &len);
		if (rc < 0 || len != entry_len) {
			rc = -1;
			goto err;
		}

		rc = next_entry(&entry_len, mmap_area, sizeof(uint32_t));
		if (rc < 0 || !entry_len) {
			rc = -1;
			goto err;
		}
		spec->lsd.study_data = (void *)mmap_area->next_addr;
		spec->lsd.flags |= PCRE_EXTRA_STUDY_DATA;
		rc = next_entry(NULL, mmap_area, entry_len);
		if (rc < 0)
			goto err;

		/* Check that study data lengths match. */
		rc = pcre_fullinfo(spec->regex, &spec->lsd,
				    PCRE_INFO_STUDYSIZE, &len);
		if (rc < 0 || len != entry_len) {
			rc = -1;
			goto err;
		}

		data->nspec++;
	}

	rc = digest_add_specfile(digest, NULL, addr, mmap_stat.st_size,
								    mmap_path);
	if (rc)
		goto err;

err:
	free(stem_map);

	return rc;
}

static int process_file(const char *path, const char *suffix,
			  struct selabel_handle *rec,
			  const char *prefix, struct selabel_digest *digest)
{
	FILE *fp;
	struct stat sb;
	unsigned int lineno;
	size_t line_len = 0;
	char *line_buf = NULL;
	int rc;
	char stack_path[PATH_MAX + 1];
	bool isbinary = false;
	uint32_t magic;

	/* append the path suffix if we have one */
	if (suffix) {
		rc = snprintf(stack_path, sizeof(stack_path),
					    "%s.%s", path, suffix);
		if (rc >= (int)sizeof(stack_path)) {
			errno = ENAMETOOLONG;
			return -1;
		}
		path = stack_path;
	}

	/* Open the specification file. */
	fp = fopen(path, "r");
	if (fp) {
		__fsetlocking(fp, FSETLOCKING_BYCALLER);

		if (fstat(fileno(fp), &sb) < 0)
			return -1;
		if (!S_ISREG(sb.st_mode)) {
			errno = EINVAL;
			return -1;
		}

		magic = 0;
		if (fread(&magic, sizeof magic, 1, fp) != 1) {
			if (ferror(fp)) {
				errno = EINVAL;
				fclose(fp);
				return -1;
			}
			clearerr(fp);
		}

		if (magic == SELINUX_MAGIC_COMPILED_FCONTEXT) {
			/* file_contexts.bin format */
			fclose(fp);
			fp = NULL;
			isbinary = true;
		} else {
			rewind(fp);
		}
	} else {
		/*
		 * Text file does not exist, so clear the timestamp
		 * so that we will always pass the timestamp comparison
		 * with the bin file in load_mmap().
		 */
		sb.st_mtime = 0;
	}

	rc = load_mmap(rec, path, &sb, isbinary, digest);
	if (rc == 0)
		goto out;

	if (!fp)
		return -1; /* no text or bin file */

	/*
	 * Then do detailed validation of the input and fill the spec array
	 */
	lineno = 0;
	rc = 0;
	while (getline(&line_buf, &line_len, fp) > 0) {
		rc = process_line(rec, path, prefix, line_buf, ++lineno);
		if (rc)
			goto out;
	}

	rc = digest_add_specfile(digest, fp, NULL, sb.st_size, path);

out:
	free(line_buf);
	if (fp)
		fclose(fp);
	return rc;
}

static void closef(struct selabel_handle *rec);

static int init(struct selabel_handle *rec, const struct selinux_opt *opts,
		unsigned n)
{
	struct saved_data *data = (struct saved_data *)rec->data;
	const char *path = NULL;
	const char *prefix = NULL;
	char subs_file[PATH_MAX + 1];
	int status = -1, baseonly = 0;

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
		rec->dist_subs =
		    selabel_subs_init(selinux_file_context_subs_dist_path(),
		    rec->dist_subs, rec->digest);
		rec->subs = selabel_subs_init(selinux_file_context_subs_path(),
		    rec->subs, rec->digest);
		path = selinux_file_context_path();
	} else {
		snprintf(subs_file, sizeof(subs_file), "%s.subs_dist", path);
		rec->dist_subs = selabel_subs_init(subs_file, rec->dist_subs,
							    rec->digest);
		snprintf(subs_file, sizeof(subs_file), "%s.subs", path);
		rec->subs = selabel_subs_init(subs_file, rec->subs,
							    rec->digest);
	}

	rec->spec_file = strdup(path);

	/*
	 * The do detailed validation of the input and fill the spec array
	 */
	status = process_file(path, NULL, rec, prefix, rec->digest);
	if (status)
		goto finish;

	if (rec->validating) {
		status = nodups_specs(data, path);
		if (status)
			goto finish;
	}

	if (!baseonly) {
		status = process_file(path, "homedirs", rec, prefix,
							    rec->digest);
		if (status && errno != ENOENT)
			goto finish;

		status = process_file(path, "local", rec, prefix,
							    rec->digest);
		if (status && errno != ENOENT)
			goto finish;
	}

	digest_gen_hash(rec->digest);

	status = sort_specs(data);

finish:
	if (status)
		closef(rec);

	return status;
}

/*
 * Backend interface routines
 */
static void closef(struct selabel_handle *rec)
{
	struct saved_data *data = (struct saved_data *)rec->data;
	struct mmap_area *area, *last_area;
	struct spec *spec;
	struct stem *stem;
	unsigned int i;

	for (i = 0; i < data->nspec; i++) {
		spec = &data->spec_arr[i];
		free(spec->lr.ctx_trans);
		free(spec->lr.ctx_raw);
		if (spec->from_mmap)
			continue;
		free(spec->regex_str);
		free(spec->type_str);
		if (spec->regcomp) {
			pcre_free(spec->regex);
			pcre_free_study(spec->sd);
		}
	}

	for (i = 0; i < (unsigned int)data->num_stems; i++) {
		stem = &data->stem_arr[i];
		if (stem->from_mmap)
			continue;
		free(stem->buf);
	}

	if (data->spec_arr)
		free(data->spec_arr);
	if (data->stem_arr)
		free(data->stem_arr);

	area = data->mmap_areas;
	while (area) {
		munmap(area->addr, area->len);
		last_area = area;
		area = area->next;
		free(last_area);
	}
	free(data);
}

static struct spec *lookup_common(struct selabel_handle *rec,
					     const char *key,
					     int type,
					     bool partial)
{
	struct saved_data *data = (struct saved_data *)rec->data;
	struct spec *spec_arr = data->spec_arr;
	int i, rc, file_stem, pcre_options = 0;
	mode_t mode = (mode_t)type;
	const char *buf;
	struct spec *ret = NULL;
	char *clean_key = NULL;
	const char *prev_slash, *next_slash;
	unsigned int sofar = 0;

	if (!data->nspec) {
		errno = ENOENT;
		goto finish;
	}

	/* Remove duplicate slashes */
	if ((next_slash = strstr(key, "//"))) {
		clean_key = (char *) malloc(strlen(key) + 1);
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

	if (partial)
		pcre_options |= PCRE_PARTIAL_SOFT;

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
				rc = pcre_exec(spec->regex,
						    get_pcre_extra(spec),
						    key, strlen(key), 0,
						    pcre_options, NULL, 0);
			else
				rc = pcre_exec(spec->regex,
						    get_pcre_extra(spec),
						    buf, strlen(buf), 0,
						    pcre_options, NULL, 0);
			if (rc == 0) {
				spec->matches++;
				break;
			} else if (partial && rc == PCRE_ERROR_PARTIAL)
				break;

			if (rc == PCRE_ERROR_NOMATCH)
				continue;

			errno = ENOENT;
			/* else it's an error */
			goto finish;
		}
	}

	if (i < 0 || strcmp(spec_arr[i].lr.ctx_raw, "<<none>>") == 0) {
		/* No matching specification. */
		errno = ENOENT;
		goto finish;
	}

	errno = 0;
	ret = &spec_arr[i];

finish:
	free(clean_key);
	return ret;
}

static struct selabel_lookup_rec *lookup(struct selabel_handle *rec,
					 const char *key, int type)
{
	struct spec *spec;

	spec = lookup_common(rec, key, type, false);
	if (spec)
		return &spec->lr;
	return NULL;
}

static bool partial_match(struct selabel_handle *rec, const char *key)
{
	return lookup_common(rec, key, 0, true) ? true : false;
}

static struct selabel_lookup_rec *lookup_best_match(struct selabel_handle *rec,
						    const char *key,
						    const char **aliases,
						    int type)
{
	size_t n, i;
	int best = -1;
	struct spec **specs;
	size_t prefix_len = 0;
	struct selabel_lookup_rec *lr = NULL;

	if (!aliases || !aliases[0])
		return lookup(rec, key, type);

	for (n = 0; aliases[n]; n++)
		;

	specs = calloc(n+1, sizeof(struct spec *));
	if (!specs)
		return NULL;
	specs[0] = lookup_common(rec, key, type, false);
	if (specs[0]) {
		if (!specs[0]->hasMetaChars) {
			/* exact match on key */
			lr = &specs[0]->lr;
			goto out;
		}
		best = 0;
		prefix_len = specs[0]->prefix_len;
	}
	for (i = 1; i <= n; i++) {
		specs[i] = lookup_common(rec, aliases[i-1], type, false);
		if (specs[i]) {
			if (!specs[i]->hasMetaChars) {
				/* exact match on alias */
				lr = &specs[i]->lr;
				goto out;
			}
			if (specs[i]->prefix_len > prefix_len) {
				best = i;
				prefix_len = specs[i]->prefix_len;
			}
		}
	}

	if (best >= 0) {
		/* longest fixed prefix match on key or alias */
		lr = &specs[best]->lr;
	} else {
		errno = ENOENT;
	}

out:
	free(specs);
	return lr;
}

static enum selabel_cmp_result incomp(struct spec *spec1, struct spec *spec2, const char *reason, int i, int j)
{
	selinux_log(SELINUX_INFO,
		    "selabel_cmp: mismatched %s on entry %d: (%s, %x, %s) vs entry %d: (%s, %x, %s)\n",
		    reason,
		    i, spec1->regex_str, spec1->mode, spec1->lr.ctx_raw,
		    j, spec2->regex_str, spec2->mode, spec2->lr.ctx_raw);
	return SELABEL_INCOMPARABLE;
}

static enum selabel_cmp_result cmp(struct selabel_handle *h1,
				   struct selabel_handle *h2)
{
	struct saved_data *data1 = (struct saved_data *)h1->data;
	struct saved_data *data2 = (struct saved_data *)h2->data;
	unsigned int i, nspec1 = data1->nspec, j, nspec2 = data2->nspec;
	struct spec *spec_arr1 = data1->spec_arr, *spec_arr2 = data2->spec_arr;
	struct stem *stem_arr1 = data1->stem_arr, *stem_arr2 = data2->stem_arr;
	bool skipped1 = false, skipped2 = false;

	i = 0;
	j = 0;
	while (i < nspec1 && j < nspec2) {
		struct spec *spec1 = &spec_arr1[i];
		struct spec *spec2 = &spec_arr2[j];

		/*
		 * Because sort_specs() moves exact pathnames to the
		 * end, we might need to skip over additional regex
		 * entries that only exist in one of the configurations.
		 */
		if (!spec1->hasMetaChars && spec2->hasMetaChars) {
			j++;
			skipped2 = true;
			continue;
		}

		if (spec1->hasMetaChars && !spec2->hasMetaChars) {
			i++;
			skipped1 = true;
			continue;
		}

		if (spec1->regcomp && spec2->regcomp) {
			size_t len1, len2;
			int rc;

			rc = pcre_fullinfo(spec1->regex, NULL, PCRE_INFO_SIZE, &len1);
			assert(rc == 0);
			rc = pcre_fullinfo(spec2->regex, NULL, PCRE_INFO_SIZE, &len2);
			assert(rc == 0);
			if (len1 != len2 ||
			    memcmp(spec1->regex, spec2->regex, len1))
				return incomp(spec1, spec2, "regex", i, j);
		} else {
			if (strcmp(spec1->regex_str, spec2->regex_str))
				return incomp(spec1, spec2, "regex_str", i, j);
		}

		if (spec1->mode != spec2->mode)
			return incomp(spec1, spec2, "mode", i, j);

		if (spec1->stem_id == -1 && spec2->stem_id != -1)
			return incomp(spec1, spec2, "stem_id", i, j);
		if (spec2->stem_id == -1 && spec1->stem_id != -1)
			return incomp(spec1, spec2, "stem_id", i, j);
		if (spec1->stem_id != -1 && spec2->stem_id != -1) {
			struct stem *stem1 = &stem_arr1[spec1->stem_id];
			struct stem *stem2 = &stem_arr2[spec2->stem_id];
			if (stem1->len != stem2->len ||
			    strncmp(stem1->buf, stem2->buf, stem1->len))
				return incomp(spec1, spec2, "stem", i, j);
		}

		if (strcmp(spec1->lr.ctx_raw, spec2->lr.ctx_raw))
			return incomp(spec1, spec2, "ctx_raw", i, j);

		i++;
		j++;
	}

	if ((skipped1 || i < nspec1) && !skipped2)
		return SELABEL_SUPERSET;
	if ((skipped2 || j < nspec2) && !skipped1)
		return SELABEL_SUBSET;
	if (skipped1 && skipped2)
		return SELABEL_INCOMPARABLE;
	return SELABEL_EQUAL;
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

int selabel_file_init(struct selabel_handle *rec,
				    const struct selinux_opt *opts,
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
	rec->func_partial_match = &partial_match;
	rec->func_lookup_best_match = &lookup_best_match;
	rec->func_cmp = &cmp;

	return init(rec, opts, nopts);
}
