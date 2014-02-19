/*
 * This file describes the internal interface used by the labeler
 * for calling the user-supplied memory allocation, validation,
 * and locking routine.
 *
 * Author : Eamon Walsh <ewalsh@epoch.ncsc.mil>
 */
#ifndef _SELABEL_INTERNAL_H_
#define _SELABEL_INTERNAL_H_

#include <stdlib.h>
#include <stdarg.h>
#include <selinux/selinux.h>
#include <selinux/label.h>
#include "dso.h"

/*
 * Installed backends
 */
int selabel_file_init(struct selabel_handle *rec, struct selinux_opt *opts,
		      unsigned nopts) hidden;
int selabel_media_init(struct selabel_handle *rec, struct selinux_opt *opts,
		      unsigned nopts) hidden;
int selabel_x_init(struct selabel_handle *rec, struct selinux_opt *opts,
		   unsigned nopts) hidden;
int selabel_db_init(struct selabel_handle *rec,
		    struct selinux_opt *opts, unsigned nopts) hidden;
int selabel_property_init(struct selabel_handle *rec,
			  struct selinux_opt *opts, unsigned nopts) hidden;

/*
 * Labeling internal structures
 */
struct selabel_sub {
	char *src;
	int slen;
	char *dst;
	struct selabel_sub *next;
};

extern struct selabel_sub *selabel_subs_init(const char *path,
					     struct selabel_sub *list);

struct selabel_lookup_rec {
	char * ctx_raw;
	char * ctx_trans;
	int validated;
};

struct selabel_handle {
	/* arguments that were passed to selabel_open */
	unsigned int backend;
	int validating;

	/* labeling operations */
	struct selabel_lookup_rec *(*func_lookup) (struct selabel_handle *h,
						   const char *key, int type);
	void (*func_close) (struct selabel_handle *h);
	void (*func_stats) (struct selabel_handle *h);

	/* supports backend-specific state information */
	void *data;

	/*
	 * The main spec file used. Note for file contexts the local and/or
	 * homedirs could also have been used to resolve a context.
	 */
	char *spec_file;

	/* substitution support */
	struct selabel_sub *dist_subs;
	struct selabel_sub *subs;
};

/*
 * Validation function
 */
extern int
selabel_validate(struct selabel_handle *rec,
		 struct selabel_lookup_rec *contexts) hidden;

/*
 * Compatibility support
 */
extern int myprintf_compat;
extern void __attribute__ ((format(printf, 1, 2)))
(*myprintf) (const char *fmt,...);

#define COMPAT_LOG(type, fmt...) if (myprintf_compat)	  \
		myprintf(fmt);				  \
	else						  \
		selinux_log(type, fmt);

extern int
compat_validate(struct selabel_handle *rec,
		struct selabel_lookup_rec *contexts,
		const char *path, unsigned lineno) hidden;

#endif				/* _SELABEL_INTERNAL_H_ */
