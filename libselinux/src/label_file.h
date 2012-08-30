#ifndef _SELABEL_FILE_H_
#define _SELABEL_FILE_H_

#include <sys/stat.h>

#include "label_internal.h"

/* A file security context specification. */
struct spec {
	struct selabel_lookup_rec lr;	/* holds contexts for lookup result */
	char *regex_str;	/* regular expession string for diagnostics */
	char *type_str;		/* type string for diagnostic messages */
	pcre *regex;		/* compiled regular expression */
	pcre_extra *sd;		/* extra compiled stuff */
	char regcomp;		/* regex_str has been compiled to regex */
	mode_t mode;		/* mode format value */
	int matches;		/* number of matching pathnames */
	int hasMetaChars;	/* regular expression has meta-chars */
	int stem_id;		/* indicates which stem-compression item */
};

/* A regular expression stem */
struct stem {
	char *buf;
	int len;
};

/* Our stored configuration */
struct saved_data {
	/*
	 * The array of specifications, initially in the same order as in
	 * the specification file. Sorting occurs based on hasMetaChars.
	 */
	struct spec *spec_arr;
	unsigned int nspec;
	unsigned int alloc_specs;

	/*
	 * The array of regular expression stems.
	 */
	struct stem *stem_arr;
	int num_stems;
	int alloc_stems;
};

static inline pcre_extra *get_pcre_extra(struct spec *spec)
{
	return spec->sd;
}

static inline mode_t string_to_mode(char *mode)
{
	size_t len;

	if (!mode)
		return 0;
	len = strlen(mode);
	if (mode[0] != '-' || len != 2)
		return -1;
	switch (mode[1]) {
	case 'b':
		return S_IFBLK;
	case 'c':
		return S_IFCHR;
	case 'd':
		return S_IFDIR;
	case 'p':
		return S_IFIFO;
	case 'l':
		return S_IFLNK;
	case 's':
		return S_IFSOCK;
	case '-':
		return S_IFREG;
	default:
		return -1;
	}
	/* impossible to get here */
	return 0;
}

static inline int grow_specs(struct saved_data *data)
{
	struct spec *specs;
	size_t new_specs, total_specs;

	if (data->nspec < data->alloc_specs)
		return 0;

	new_specs = data->nspec + 16;
	total_specs = data->nspec + new_specs;

	specs = realloc(data->spec_arr, total_specs * sizeof(*specs));
	if (!specs) {
		perror("realloc");
		return -1;
	}

	/* blank the new entries */
	memset(&specs[data->nspec], 0, new_specs * sizeof(*specs));

	data->spec_arr = specs;
	data->alloc_specs = total_specs;
	return 0;
}

/* Determine if the regular expression specification has any meta characters. */
static inline void spec_hasMetaChars(struct spec *spec)
{
	char *c;
	int len;
	char *end;

	c = spec->regex_str;
	len = strlen(spec->regex_str);
	end = c + len;

	spec->hasMetaChars = 0;

	/* Look at each character in the RE specification string for a
	 * meta character. Return when any meta character reached. */
	while (c < end) {
		switch (*c) {
		case '.':
		case '^':
		case '$':
		case '?':
		case '*':
		case '+':
		case '|':
		case '[':
		case '(':
		case '{':
			spec->hasMetaChars = 1;
			return;
		case '\\':	/* skip the next character */
			c++;
			break;
		default:
			break;

		}
		c++;
	}
	return;
}

/* Move exact pathname specifications to the end. */
static inline int sort_specs(struct saved_data *data)
{
	struct spec *spec_copy;
	int i, j;

	spec_copy = malloc(sizeof(*spec_copy) * data->nspec);
	if (!spec_copy)
		return -1;
	j = 0;
	for (i = 0; i < data->nspec; i++)
		if (data->spec_arr[i].hasMetaChars)
			memcpy(&spec_copy[j++], &data->spec_arr[i], sizeof(spec_copy[j]));
	for (i = 0; i < data->nspec; i++)
		if (!data->spec_arr[i].hasMetaChars)
			memcpy(&spec_copy[j++], &data->spec_arr[i], sizeof(spec_copy[j]));
	free(data->spec_arr);
	data->spec_arr = spec_copy;

	return 0;
}

/* Return the length of the text that can be considered the stem, returns 0
 * if there is no identifiable stem */
static inline int get_stem_from_spec(const char *const buf)
{
	const char *tmp = strchr(buf + 1, '/');
	const char *ind;

	if (!tmp)
		return 0;

	for (ind = buf; ind < tmp; ind++) {
		if (strchr(".^$?*+|[({", (int)*ind))
			return 0;
	}
	return tmp - buf;
}

/*
 * return the stemid given a string and a length
 */
static inline int find_stem(struct saved_data *data, const char *buf, int stem_len)
{
	int i;

	for (i = 0; i < data->num_stems; i++) {
		if (stem_len == data->stem_arr[i].len &&
		    !strncmp(buf, data->stem_arr[i].buf, stem_len))
			return i;
	}

	return -1;
}

/* returns the index of the new stored object */
static inline int store_stem(struct saved_data *data, char *buf, int stem_len)
{
	int num = data->num_stems;

	if (data->alloc_stems == num) {
		struct stem *tmp_arr;

		data->alloc_stems = data->alloc_stems * 2 + 16;
		tmp_arr = realloc(data->stem_arr,
				  sizeof(*tmp_arr) * data->alloc_stems);
		if (!tmp_arr)
			return -1;
		data->stem_arr = tmp_arr;
	}
	data->stem_arr[num].len = stem_len;
	data->stem_arr[num].buf = buf;
	data->num_stems++;

	return num;
}

/* find the stem of a file spec, returns the index into stem_arr for a new
 * or existing stem, (or -1 if there is no possible stem - IE for a file in
 * the root directory or a regex that is too complex for us). */
static inline int find_stem_from_spec(struct saved_data *data, const char *buf)
{
	int stem_len = get_stem_from_spec(buf);
	int stemid;
	char *stem;

	if (!stem_len)
		return -1;

	stemid = find_stem(data, buf, stem_len);
	if (stemid >= 0)
		return stemid;

	/* not found, allocate a new one */
	stem = strndup(buf, stem_len);
	if (!stem)
		return -1;

	return store_stem(data, stem, stem_len);
}

#endif /* _SELABEL_FILE_H_ */
