#ifndef _SELABEL_FILE_H_
#define _SELABEL_FILE_H_

#include <sys/stat.h>

#include "label_internal.h"

#define SELINUX_MAGIC_COMPILED_FCONTEXT	0xf97cff8a
#define SELINUX_COMPILED_FCONTEXT_NOPCRE_VERS	1
#define SELINUX_COMPILED_FCONTEXT_PCRE_VERS	2
#define SELINUX_COMPILED_FCONTEXT_MAX_VERS	2

/* Prior to verison 8.20, libpcre did not have pcre_free_study() */
#if (PCRE_MAJOR < 8 || (PCRE_MAJOR == 8 && PCRE_MINOR < 20))
#define pcre_free_study  pcre_free
#endif

/* A file security context specification. */
struct spec {
	struct selabel_lookup_rec lr;	/* holds contexts for lookup result */
	char *regex_str;	/* regular expession string for diagnostics */
	char *type_str;		/* type string for diagnostic messages */
	pcre *regex;		/* compiled regular expression */
	union {
		pcre_extra *sd;	/* pointer to extra compiled stuff */
		pcre_extra lsd;	/* used to hold the mmap'd version */
	};
	mode_t mode;		/* mode format value */
	int matches;		/* number of matching pathnames */
	int stem_id;		/* indicates which stem-compression item */
	char hasMetaChars;	/* regular expression has meta-chars */
	char regcomp;		/* regex_str has been compiled to regex */
	char from_mmap;		/* this spec is from an mmap of the data */
};

/* A regular expression stem */
struct stem {
	char *buf;
	int len;
	char from_mmap;
};

/* Where we map the file in during selabel_open() */
struct mmap_area {
	void *addr;
	size_t len;
	struct mmap_area *next;
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
	struct mmap_area *mmap_areas;
};

static inline pcre_extra *get_pcre_extra(struct spec *spec)
{
	if (spec->from_mmap)
		return &spec->lsd;
	else
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
	struct spec spec;
	unsigned int i;
	int front, back;
	size_t len = sizeof(*spec_copy);

	spec_copy = malloc(len * data->nspec);
	if (!spec_copy)
		return -1;

	/* first move the exact pathnames to the back */
	front = 0;
	back = data->nspec - 1;
	for (i = 0; i < data->nspec; i++) {
		if (data->spec_arr[i].hasMetaChars)
			memcpy(&spec_copy[front++], &data->spec_arr[i], len);
		else
			memcpy(&spec_copy[back--], &data->spec_arr[i], len);
	}

	/*
	 * now the exact pathnames are at the end, but they are in the reverse order.
	 * since 'front' is now the first of the 'exact' we can run that part of the
	 * array switching the front and back element.
	 */
	back = data->nspec - 1;
	while (front < back) {
		/* save the front */
		memcpy(&spec, &spec_copy[front], len);
		/* move the back to the front */
		memcpy(&spec_copy[front], &spec_copy[back], len);
		/* put the old front in the back */
		memcpy(&spec_copy[back], &spec, len);
		front++;
		back--;
	}

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
