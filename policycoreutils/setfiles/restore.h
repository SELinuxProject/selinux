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
#include <stdlib.h>
#include <limits.h>
#include <stdint.h>

#define STAR_COUNT 1024

/* Things that need to be init'd */
struct restore_opts {
	int add_assoc; /* Track inode associations for conflict detection. */
	int progress;
	uint64_t count;  /* Number of files processed so far */
	uint64_t nfile;  /* Estimated total number of files */
	int debug;
	int change;
	int hard_links;
	int verbose;
	int logging;
	int ignore_enoent;
	char *rootpath;
	int rootpathlen;
	char *progname;
	FILE *outfile;
	int force;
	struct selabel_handle *hnd;
	int expand_realpath;  /* Expand paths via realpath. */
	int abort_on_error; /* Abort the file tree walk upon an error. */
	int quiet;
	int fts_flags; /* Flags to fts, e.g. follow links, follow mounts */
	const char *selabel_opt_validate;
	const char *selabel_opt_path;
};

void restore_init(struct restore_opts *opts);
void restore_finish(void);
int add_exclude(const char *directory);
int exclude(const char *path);
void remove_exclude(const char *directory);
int process_one_realpath(char *name, int recurse);
int process_glob(char *name, int recurse);
int exclude_non_seclabel_mounts(void);

#endif
