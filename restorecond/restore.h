#ifndef RESTORE_H
#define RESTORE_H
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>
#include <sys/stat.h>
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
	unsigned int set_specctx;
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
	unsigned int skip_multilink;
	/* restorecon_flags holds | of above for restore_init() */
	unsigned int restorecon_flags;
	char *rootpath;
	char *progname;
	struct selabel_handle *hnd;
	const char *selabel_opt_validate;
	const char *selabel_opt_path;
	const char *selabel_opt_digest;
	int debug;
	FILE *outfile;
};

void restore_init(struct restore_opts *opts);
extern char **exclude_list;

#endif
