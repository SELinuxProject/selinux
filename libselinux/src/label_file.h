#ifndef _SELABEL_FILE_H_
#define _SELABEL_FILE_H_

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
#endif /* _SELABEL_FILE_H_ */
