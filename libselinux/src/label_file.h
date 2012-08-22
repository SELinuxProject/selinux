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
	unsigned int ncomp;

	/*
	 * The array of regular expression stems.
	 */
	struct stem *stem_arr;
	int num_stems;
	int alloc_stems;
};

static inline mode_t string_to_mode(char *mode, const char *path, unsigned lineno)
{
	size_t len;

	len = strlen(mode);
	if (mode[0] != '-' || len != 2) {
		COMPAT_LOG(SELINUX_WARNING,
			    "%s:  line %d has invalid file type %s\n",
			    path, lineno, mode);
		return 0;
	}
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
		COMPAT_LOG(SELINUX_WARNING,
			    "%s:  line %d has invalid file type %s\n",
			    path, lineno, mode);
		return 0;
	}
	/* impossible to get here */
	return 0;
}

#endif /* _SELABEL_FILE_H_ */
