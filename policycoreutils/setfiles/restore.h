#ifndef RESTORE_H
#define RESTORE_H
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <fts.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sepol/sepol.h>
#include <selinux/selinux.h>
#include <selinux/label.h>
#include <selinux/restorecon.h>
#include <stdlib.h>
#include <limits.h>
#include <stdint.h>

/* Things that need to be init'd */
struct restore_opts {
	unsigned int nochange;
	unsigned int verbose;
	unsigned int progress;
	unsigned int mass_relabel;
	unsigned int set_specctx;
	unsigned int set_user_role;
	unsigned int add_assoc;
	unsigned int ignore_digest;
	unsigned int recurse;
	unsigned int userealpath;
	unsigned int xdev;
	unsigned int abort_on_error;
	unsigned int syslog_changes;
	unsigned int log_matches;
	unsigned int ignore_noent;
	unsigned int ignore_mounts;
	unsigned int conflict_error;
	unsigned int count_errors;
	/* restorecon_flags holds | of above for restore_init() */
	unsigned int restorecon_flags;
	char *rootpath;
	char *progname;
	struct selabel_handle *hnd;
	const char *selabel_opt_validate;
	const char *selabel_opt_path;
	const char *selabel_opt_digest;
	int debug;
};

void restore_init(struct restore_opts *opts);
void restore_finish(void);
void add_exclude(const char *directory);
int process_glob(char *name, struct restore_opts *opts, size_t nthreads,
		 long unsigned *skipped_errors);
extern char **exclude_list;

#endif
