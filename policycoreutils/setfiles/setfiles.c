#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <regex.h>
#include <sys/vfs.h>
#include <sys/utsname.h>
#define __USE_XOPEN_EXTENDED 1	/* nftw */
#define SKIP -2
#define ERR -1
#include <fts.h>
#include <limits.h>
#include <sepol/sepol.h>
#include <selinux/selinux.h>
#include <selinux/label.h>
#include <syslog.h>
#include <libgen.h>
#ifdef USE_AUDIT
#include <libaudit.h>

#ifndef AUDIT_FS_RELABEL
#define AUDIT_FS_RELABEL 2309
#endif
#endif
static int mass_relabel;
static int mass_relabel_errs;

#define STAR_COUNT 1000

static FILE *outfile = NULL;
static int force = 0;
#define STAT_BLOCK_SIZE 1
static int progress = 0;
static unsigned long long count = 0;

#define MAX_EXCLUDES 1000
static int excludeCtr = 0;
struct edir {
	char *directory;
	size_t size;
};
static struct edir excludeArray[MAX_EXCLUDES];

/*
 * Command-line options.
 */
static char *policyfile = NULL;
static int debug = 0;
static int change = 1;
static int quiet = 0;
static int ignore_enoent;
static int verbose = 0;
static int logging = 0;
static int warn_no_match = 0;
static int null_terminated = 0;
static char *rootpath = NULL;
static int rootpathlen = 0;
static int recurse; /* Recursive descent. */
static int errors;

static char *progname;

#define SETFILES "setfiles"
#define RESTORECON "restorecon"
static int iamrestorecon;

/* Behavior flags determined based on setfiles vs. restorecon */
static int expand_realpath;  /* Expand paths via realpath. */
static int abort_on_error; /* Abort the file tree walk upon an error. */
static int add_assoc; /* Track inode associations for conflict detection. */
static int fts_flags; /* Flags to fts, e.g. follow links, follow mounts */
static int ctx_validate; /* Validate contexts */
static const char *altpath; /* Alternate path to file_contexts */

/* Label interface handle */
static struct selabel_handle *hnd;

/*
 * An association between an inode and a context.
 */
typedef struct file_spec {
	ino_t ino;		/* inode number */
	char *con;		/* matched context */
	char *file;		/* full pathname */
	struct file_spec *next;	/* next association in hash bucket chain */
} file_spec_t;

/*
 * The hash table of associations, hashed by inode number.
 * Chaining is used for collisions, with elements ordered
 * by inode number in each bucket.  Each hash bucket has a dummy 
 * header.
 */
#define HASH_BITS 16
#define HASH_BUCKETS (1 << HASH_BITS)
#define HASH_MASK (HASH_BUCKETS-1)
static file_spec_t *fl_head;

/*
 * Try to add an association between an inode and a context.
 * If there is a different context that matched the inode,
 * then use the first context that matched.
 */
int filespec_add(ino_t ino, const security_context_t con, const char *file)
{
	file_spec_t *prevfl, *fl;
	int h, ret;
	struct stat sb;

	if (!fl_head) {
		fl_head = malloc(sizeof(file_spec_t) * HASH_BUCKETS);
		if (!fl_head)
			goto oom;
		memset(fl_head, 0, sizeof(file_spec_t) * HASH_BUCKETS);
	}

	h = (ino + (ino >> HASH_BITS)) & HASH_MASK;
	for (prevfl = &fl_head[h], fl = fl_head[h].next; fl;
	     prevfl = fl, fl = fl->next) {
		if (ino == fl->ino) {
			ret = lstat(fl->file, &sb);
			if (ret < 0 || sb.st_ino != ino) {
				freecon(fl->con);
				free(fl->file);
				fl->file = strdup(file);
				if (!fl->file)
					goto oom;
				fl->con = strdup(con);
				if (!fl->con)
					goto oom;
				return 1;
			}

			if (strcmp(fl->con, con) == 0)
				return 1;

			fprintf(stderr,
				"%s:  conflicting specifications for %s and %s, using %s.\n",
				__FUNCTION__, file, fl->file, fl->con);
			free(fl->file);
			fl->file = strdup(file);
			if (!fl->file)
				goto oom;
			return 1;
		}

		if (ino > fl->ino)
			break;
	}

	fl = malloc(sizeof(file_spec_t));
	if (!fl)
		goto oom;
	fl->ino = ino;
	fl->con = strdup(con);
	if (!fl->con)
		goto oom_freefl;
	fl->file = strdup(file);
	if (!fl->file)
		goto oom_freefl;
	fl->next = prevfl->next;
	prevfl->next = fl;
	return 0;
      oom_freefl:
	free(fl);
      oom:
	fprintf(stderr,
		"%s:  insufficient memory for file label entry for %s\n",
		__FUNCTION__, file);
	return -1;
}

/*
 * Evaluate the association hash table distribution.
 */
void filespec_eval(void)
{
	file_spec_t *fl;
	int h, used, nel, len, longest;

	if (!fl_head)
		return;

	used = 0;
	longest = 0;
	nel = 0;
	for (h = 0; h < HASH_BUCKETS; h++) {
		len = 0;
		for (fl = fl_head[h].next; fl; fl = fl->next) {
			len++;
		}
		if (len)
			used++;
		if (len > longest)
			longest = len;
		nel += len;
	}

	printf
	    ("%s:  hash table stats: %d elements, %d/%d buckets used, longest chain length %d\n",
	     __FUNCTION__, nel, used, HASH_BUCKETS, longest);
}

/*
 * Destroy the association hash table.
 */
void filespec_destroy(void)
{
	file_spec_t *fl, *tmp;
	int h;

	if (!fl_head)
		return;

	for (h = 0; h < HASH_BUCKETS; h++) {
		fl = fl_head[h].next;
		while (fl) {
			tmp = fl;
			fl = fl->next;
			freecon(tmp->con);
			free(tmp->file);
			free(tmp);
		}
		fl_head[h].next = NULL;
	}
	free(fl_head);
	fl_head = NULL;
}

static int add_exclude(const char *directory)
{
	size_t len = 0;

	if (directory == NULL || directory[0] != '/') {
		fprintf(stderr, "Full path required for exclude: %s.\n",
			directory);
		return 1;
	}
	if (excludeCtr == MAX_EXCLUDES) {
		fprintf(stderr, "Maximum excludes %d exceeded.\n",
			MAX_EXCLUDES);
		return 1;
	}

	len = strlen(directory);
	while (len > 1 && directory[len - 1] == '/') {
		len--;
	}
	excludeArray[excludeCtr].directory = strndup(directory, len);

	if (excludeArray[excludeCtr].directory == NULL) {
		fprintf(stderr, "Out of memory.\n");
		return 1;
	}
	excludeArray[excludeCtr++].size = len;

	return 0;
}

static void remove_exclude(const char *directory)
{
	int i = 0;
	for (i = 0; i < excludeCtr; i++) {
		if (strcmp(directory, excludeArray[i].directory) == 0) {
			free(excludeArray[i].directory);
			if (i != excludeCtr-1)
				excludeArray[i] = excludeArray[excludeCtr-1];
			excludeCtr--;
			return;
		}
	}
	return;
}

static int exclude(const char *file)
{
	int i = 0;
	for (i = 0; i < excludeCtr; i++) {
		if (strncmp
		    (file, excludeArray[i].directory,
		     excludeArray[i].size) == 0) {
			if (file[excludeArray[i].size] == 0
			    || file[excludeArray[i].size] == '/') {
				return 1;
			}
		}
	}
	return 0;
}

int match(const char *name, struct stat *sb, char **con)
{
	if (NULL != rootpath) {
		if (0 != strncmp(rootpath, name, rootpathlen)) {
			fprintf(stderr, "%s:  %s is not located in %s\n",
				progname, name, rootpath);
			return -1;
		}
		name += rootpathlen;
	}

	if (rootpath != NULL && name[0] == '\0')
		/* this is actually the root dir of the alt root */
		return selabel_lookup_raw(hnd, con, "/", sb->st_mode);
	else
		return selabel_lookup_raw(hnd, con, name, sb->st_mode);
}

void usage(const char *const name)
{
	if (iamrestorecon) {
		fprintf(stderr,
			"usage:  %s [-iFnrRv0] [-e excludedir ] [-o filename ] [-f filename | pathname... ]\n",
			name);
	} else {
		fprintf(stderr,
			"usage:  %s [-dnpqvW] [-o filename] [-r alt_root_path ] spec_file pathname...\n"
			"usage:  %s -c policyfile spec_file\n"
			"usage:  %s -s [-dnqvW] [-o filename ] spec_file\n", name, name,
			name);
	}
	exit(1);
}

static int nerr = 0;

void inc_err()
{
	nerr++;
	if (nerr > 9 && !debug) {
		fprintf(stderr, "Exiting after 10 errors.\n");
		exit(1);
	}
}

/* Compare two contexts to see if their differences are "significant",
 * or whether the only difference is in the user. */
static int only_changed_user(const char *a, const char *b)
{
	char *rest_a, *rest_b;	/* Rest of the context after the user */
	if (force)
		return 0;
	if (!a || !b)
		return 0;
	rest_a = strchr(a, ':');
	rest_b = strchr(b, ':');
	if (!rest_a || !rest_b)
		return 0;
	return (strcmp(rest_a, rest_b) == 0);
}

static int restore(FTSENT *ftsent)
{
	char *my_file = strdupa(ftsent->fts_path);
	int ret;
	char *context, *newcon;
	int user_only_changed = 0;

	if (match(my_file, ftsent->fts_statp, &newcon) < 0)
		/* Check for no matching specification. */
		return (errno == ENOENT) ? 0 : -1;

	if (progress) {
		count++;
		if (count % (80 * STAR_COUNT) == 0) {
			fprintf(stdout, "\n");
			fflush(stdout);
		}
		if (count % STAR_COUNT == 0) {
			fprintf(stdout, "*");
			fflush(stdout);
		}
	}

	/*
	 * Try to add an association between this inode and
	 * this specification.  If there is already an association
	 * for this inode and it conflicts with this specification,
	 * then use the last matching specification.
	 */
	if (add_assoc) {
		ret = filespec_add(ftsent->fts_statp->st_ino, newcon, my_file);
		if (ret < 0)
			goto err;

		if (ret > 0)
			/* There was already an association and it took precedence. */
			goto out;
	}

	if (debug) {
		printf("%s:  %s matched by %s\n", progname, my_file, newcon);
	}

	/* Get the current context of the file. */
	ret = lgetfilecon_raw(ftsent->fts_accpath, &context);
	if (ret < 0) {
		if (errno == ENODATA) {
			context = NULL;
		} else {
			fprintf(stderr, "%s get context on %s failed: '%s'\n",
				progname, my_file, strerror(errno));
			goto err;
		}
		user_only_changed = 0;
	} else
		user_only_changed = only_changed_user(context, newcon);

	/*
	 * Do not relabel the file if the matching specification is 
	 * <<none>> or the file is already labeled according to the 
	 * specification.
	 */
	if ((strcmp(newcon, "<<none>>") == 0) ||
	    (context && (strcmp(context, newcon) == 0))) {
		freecon(context);
		goto out;
	}

	if (!force && context && (is_context_customizable(context) > 0)) {
		if (verbose > 1) {
			fprintf(stderr,
				"%s: %s not reset customized by admin to %s\n",
				progname, my_file, context);
		}
		freecon(context);
		goto out;
	}

	if (verbose) {
		/* If we're just doing "-v", trim out any relabels where
		 * the user has changed but the role and type are the
		 * same.  For "-vv", emit everything. */
		if (verbose > 1 || !user_only_changed) {
			printf("%s reset %s context %s->%s\n",
			       progname, my_file, context ?: "", newcon);
		}
	}

	if (logging && !user_only_changed) {
		if (context)
			syslog(LOG_INFO, "relabeling %s from %s to %s\n",
			       my_file, context, newcon);
		else
			syslog(LOG_INFO, "labeling %s to %s\n",
			       my_file, newcon);
	}

	if (outfile && !user_only_changed)
		fprintf(outfile, "%s\n", my_file);

	if (context)
		freecon(context);

	/*
	 * Do not relabel the file if -n was used.
	 */
	if (!change || user_only_changed)
		goto out;

	/*
	 * Relabel the file to the specified context.
	 */
	ret = lsetfilecon(ftsent->fts_accpath, newcon);
	if (ret) {
		fprintf(stderr, "%s set context %s->%s failed:'%s'\n",
			progname, my_file, newcon, strerror(errno));
		goto skip;
	}
out:
	freecon(newcon);
	return 0;
skip:
	freecon(newcon);
	return SKIP;
err:
	freecon(newcon);
	return ERR;
}

/*
 * Apply the last matching specification to a file.
 * This function is called by fts on each file during
 * the directory traversal.
 */
static int apply_spec(FTSENT *ftsent)
{
	if (ftsent->fts_info == FTS_DNR) {
		fprintf(stderr, "%s:  unable to read directory %s\n",
			progname, ftsent->fts_path);
		return SKIP;
	}

	int rc = restore(ftsent);
	if (rc == ERR) {
		if (!abort_on_error)
			return SKIP;
	}
	return rc;
}

void set_rootpath(const char *arg)
{
	int len;

	rootpath = strdup(arg);
	if (NULL == rootpath) {
		fprintf(stderr, "%s:  insufficient memory for rootpath\n",
			progname);
		exit(1);
	}

	/* trim trailing /, if present */
	len = strlen(rootpath);
	while (len && ('/' == rootpath[len - 1]))
		rootpath[--len] = 0;
	rootpathlen = len;
}

int canoncon(char **contextp)
{
	char *context = *contextp, *tmpcon;
	int rc = 0;

	if (policyfile) {
		if (sepol_check_context(context) < 0) {
			fprintf(stderr, "invalid context %s\n", context);
			exit(1);
		}
	} else if (security_canonicalize_context_raw(context, &tmpcon) == 0) {
		free(context);
		*contextp = tmpcon;
	} else if (errno != ENOENT) {
		rc = -1;
		inc_err();
	}

	return rc;
}

static int symlink_realpath(char *name, char *path)
{
	char *p = NULL, *file_sep;
	char *tmp_path = strdupa(name);
	size_t len = 0;

	if (!tmp_path) {
		fprintf(stderr, "strdupa on %s failed:  %s\n", name,
			strerror(errno));
		return -1;
	}
	file_sep = strrchr(tmp_path, '/');
	if (file_sep == tmp_path) {
		file_sep++;
		p = strcpy(path, "");
	} else if (file_sep) {
		*file_sep = 0;
		file_sep++;
		p = realpath(tmp_path, path);
	} else {
		file_sep = tmp_path;
		p = realpath("./", path);
	}
	if (p)
		len = strlen(p);
	if (!p || len + strlen(file_sep) + 2 > PATH_MAX) {
		fprintf(stderr, "symlink_realpath(%s) failed %s\n", name,
			strerror(errno));
		return -1;
	}
	p += len;
	/* ensure trailing slash of directory name */
	if (len == 0 || *(p - 1) != '/') {
		*p = '/';
		p++;
	}
	strcpy(p, file_sep);
	return 0;
}

static int process_one(char *name, int recurse_this_path)
{
	int rc = 0;
	const char *namelist[2];
	dev_t dev_num = 0;
	FTS *fts_handle;
	FTSENT *ftsent;

	if (!strcmp(name, "/"))
		mass_relabel = 1;

	namelist[0] = name;
	namelist[1] = NULL;
	fts_handle = fts_open((char **)namelist, fts_flags, NULL);
	if (fts_handle  == NULL) {
		fprintf(stderr,
			"%s: error while labeling %s:  %s\n",
			progname, namelist[0], strerror(errno));
		goto err;
	}


	ftsent = fts_read(fts_handle);
	if (ftsent != NULL) {
		/* Keep the inode of the first one. */
		dev_num = ftsent->fts_statp->st_dev;
	}

	do {
		/* Skip the post order nodes. */
		if (ftsent->fts_info == FTS_DP)
			continue;
		/* If the XDEV flag is set and the device is different */
		if (ftsent->fts_statp->st_dev != dev_num &&
		    FTS_XDEV == (fts_flags & FTS_XDEV))
			continue;
		if (excludeCtr > 0) {
			if (exclude(ftsent->fts_path)) {
				fts_set(fts_handle, ftsent, FTS_SKIP);
				continue;
			}
		}
		int rc = apply_spec(ftsent);
		if (rc == SKIP)
			fts_set(fts_handle, ftsent, FTS_SKIP);
		if (rc == ERR)
			goto err;
		if (!recurse_this_path)
			break;
	} while ((ftsent = fts_read(fts_handle)) != NULL);

	if (!strcmp(name, "/"))
		mass_relabel_errs = 0;

out:
	if (add_assoc) {
		if (!quiet)
			filespec_eval();
		filespec_destroy();
	}
	if (fts_handle)
		fts_close(fts_handle);
	return rc;

err:
	if (!strcmp(name, "/"))
		mass_relabel_errs = 1;
	rc = -1;
	goto out;
}

static int process_one_realpath(char *name)
{
	int rc = 0;
	char *p;
	struct stat sb;

	if (!expand_realpath) {
		return process_one(name, recurse);
	} else {
		rc = lstat(name, &sb);
		if (rc < 0) {
			fprintf(stderr, "%s:  lstat(%s) failed:  %s\n",
				progname, name,	strerror(errno));
			return -1;
		}

		if (S_ISLNK(sb.st_mode)) {
			char path[PATH_MAX + 1];

			rc = symlink_realpath(name, path);
			if (rc < 0)
				return rc;
			rc = process_one(path, 0);
			if (rc < 0)
				return rc;

			p = realpath(name, NULL);
			if (p) {
				rc = process_one(p, recurse);
				free(p);
			}
			return rc;
		} else {
			p = realpath(name, NULL);
			if (!p) {
				fprintf(stderr, "realpath(%s) failed %s\n", name,
					strerror(errno));
				return -1;
			}
			rc = process_one(p, recurse);
			free(p);
			return rc;
		}
	}
}

#ifndef USE_AUDIT
static void maybe_audit_mass_relabel(void)
{
#else
static void maybe_audit_mass_relabel(void)
{
	int audit_fd = -1;
	int rc = 0;

	if (!mass_relabel)		/* only audit a forced full relabel */
		return;

	audit_fd = audit_open();

	if (audit_fd < 0) {
		fprintf(stderr, "Error connecting to audit system.\n");
		exit(-1);
	}

	rc = audit_log_user_message(audit_fd, AUDIT_FS_RELABEL,
				    "op=mass relabel", NULL, NULL, NULL, !mass_relabel_errs);
	if (rc <= 0) {
		fprintf(stderr, "Error sending audit message: %s.\n",
			strerror(errno));
		/* exit(-1); -- don't exit atm. as fix for eff_cap isn't in most kernels */
	}
	audit_close(audit_fd);
#endif
}

/*
   Search /proc/mounts for all file systems that do not support extended
   attributes and add them to the exclude directory table.  File systems
   that support security labels have the seclabel option.
*/
static void exclude_non_seclabel_mounts()
{
	struct utsname uts;
	FILE *fp;
	size_t len;
	ssize_t num;
	int index = 0, found = 0;
	char *mount_info[4];
	char *buf = NULL, *item;

	/* Check to see if the kernel supports seclabel */
	if (uname(&uts) == 0 && strverscmp(uts.release, "2.6.30") < 0)
		return;

	fp = fopen("/proc/mounts", "r");
	if (!fp)
		return;

	while ((num = getline(&buf, &len, fp)) != -1) {
		found = 0;
		index = 0;
		item = strtok(buf, " ");
		while (item != NULL) {
			mount_info[index] = item;
			if (index == 3)
				break;
			index++;
			item = strtok(NULL, " ");
		}
		if (index < 3) {
			fprintf(stderr,
				"/proc/mounts record \"%s\" has incorrect format.\n",
				buf);
			continue;
		}

		/* remove pre-existing entry */
		remove_exclude(mount_info[1]);

		item = strtok(mount_info[3], ",");
		while (item != NULL) {
			if (strcmp(item, "seclabel") == 0) {
				found = 1;
				break;
			}
			item = strtok(NULL, ",");
		}

		/* exclude mount points without the seclabel option */
		if (!found)
			add_exclude(mount_info[1]);
	}

	free(buf);
}

int main(int argc, char **argv)
{
	struct stat sb;
	int opt, i = 0;
	char *input_filename = NULL;
	int use_input_file = 0;
	char *buf = NULL;
	size_t buf_len;
	char *base;
	struct selinux_opt opts[] = {
		{ SELABEL_OPT_VALIDATE, NULL },
		{ SELABEL_OPT_PATH, NULL }
	};

	memset(excludeArray, 0, sizeof(excludeArray));
	altpath = NULL;

	progname = strdup(argv[0]);
	if (!progname) {
		fprintf(stderr, "%s:  Out of memory!\n", argv[0]);
		exit(1);
	}
	base = basename(progname);
	
	if (!strcmp(base, SETFILES)) {
		/* 
		 * setfiles:  
		 * Recursive descent,
		 * Does not expand paths via realpath, 
		 * Aborts on errors during the file tree walk, 
		 * Try to track inode associations for conflict detection,
		 * Does not follow mounts,
		 * Validates all file contexts at init time. 
		 */
		iamrestorecon = 0;
		recurse = 1;
		expand_realpath = 0;
		abort_on_error = 1;
		add_assoc = 1;
		fts_flags = FTS_PHYSICAL | FTS_XDEV;
		ctx_validate = 1;
	} else {
		/*
		 * restorecon:  
		 * No recursive descent unless -r/-R,
		 * Expands paths via realpath, 
		 * Do not abort on errors during the file tree walk,
		 * Do not try to track inode associations for conflict detection,
		 * Follows mounts,
		 * Does lazy validation of contexts upon use. 
		 */
		if (strcmp(base, RESTORECON) && !quiet) 
			printf("Executed with an unrecognized name (%s), defaulting to %s behavior.\n", base, RESTORECON);
		iamrestorecon = 1;
		recurse = 0;
		expand_realpath = 1;
		abort_on_error = 0;
		add_assoc = 0;
		fts_flags = FTS_PHYSICAL;
		ctx_validate = 0;

		/* restorecon only:  silent exit if no SELinux.
		   Allows unconditional execution by scripts. */
		if (is_selinux_enabled() <= 0)
			exit(0);
	}

	/* This must happen before getopt. */
	exclude_non_seclabel_mounts();

	/* Process any options. */
	while ((opt = getopt(argc, argv, "c:de:f:ilnpqrsvo:FRW0")) > 0) {
		switch (opt) {
		case 'c':
			{
				FILE *policystream;

				if (iamrestorecon)
					usage(argv[0]);

				policyfile = optarg;

				policystream = fopen(policyfile, "r");
				if (!policystream) {
					fprintf(stderr,
						"Error opening %s: %s\n",
						policyfile, strerror(errno));
					exit(1);
				}
				__fsetlocking(policystream,
					      FSETLOCKING_BYCALLER);

				if (sepol_set_policydb_from_file(policystream) <
				    0) {
					fprintf(stderr,
						"Error reading policy %s: %s\n",
						policyfile, strerror(errno));
					exit(1);
				}
				fclose(policystream);

				ctx_validate = 1;

				break;
			}
		case 'e':
			remove_exclude(optarg);
			if (lstat(optarg, &sb) < 0 && errno != EACCES) {
				fprintf(stderr, "Can't stat exclude path \"%s\", %s - ignoring.\n",
					optarg, strerror(errno));
				break;
			}
			if (add_exclude(optarg))
				exit(1);
			break;
		case 'f':
			use_input_file = 1;
			input_filename = optarg;
			break;			
		case 'd':
			debug = 1;
			break;
		case 'i':
			ignore_enoent = 1;
			break;
		case 'l':
			logging = 1;
			break;
		case 'F':
			force = 1;
			break;
		case 'n':
			change = 0;
			break;
		case 'o':
			if (strcmp(optarg, "-") == 0) {
				outfile = stdout;
				break;
			}

			outfile = fopen(optarg, "w");
			if (!outfile) {
				fprintf(stderr, "Error opening %s: %s\n",
					optarg, strerror(errno));

				usage(argv[0]);
			}
			__fsetlocking(outfile, FSETLOCKING_BYCALLER);
			break;
		case 'q':
			quiet = 1;
			break;
		case 'R':
		case 'r':
			if (iamrestorecon) {
				recurse = 1;
				break;
			}
			if (optind + 1 >= argc) {
				fprintf(stderr, "usage:  %s -r rootpath\n",
					argv[0]);
				exit(1);
			}
			if (NULL != rootpath) {
				fprintf(stderr,
					"%s: only one -r can be specified\n",
					argv[0]);
				exit(1);
			}
			set_rootpath(argv[optind++]);
			break;
		case 's':
			use_input_file = 1;
			input_filename = "-";
			add_assoc = 0;
			break;
		case 'v':
			if (progress) {
				fprintf(stderr,
					"Progress and Verbose mutually exclusive\n");
				exit(1);
			}
			verbose++;
			break;
		case 'p':
			if (verbose) {
				fprintf(stderr,
					"Progress and Verbose mutually exclusive\n");
				usage(argv[0]);
			}
			progress = 1;
			break;
		case 'W':
			warn_no_match = 1;
			break;
		case '0':
			null_terminated = 1;
			break;
		case '?':
			usage(argv[0]);
		}
	}

	if (!iamrestorecon) {
		if (policyfile) {
			if (optind != (argc - 1))
				usage(argv[0]);
		} else if (use_input_file) {
			if (optind != (argc - 1)) {
				/* Cannot mix with pathname arguments. */
				usage(argv[0]);
			}
		} else {
			if (optind > (argc - 2))
				usage(argv[0]);
		}

		/* Use our own invalid context checking function so that
		   we can support either checking against the active policy or
		   checking against a binary policy file. */
		selinux_set_callback(SELINUX_CB_VALIDATE,
				     (union selinux_callback)&canoncon);

		if (stat(argv[optind], &sb) < 0) {
			perror(argv[optind]);
			exit(1);
		}
		if (!S_ISREG(sb.st_mode)) {
			fprintf(stderr, "%s:  spec file %s is not a regular file.\n",
				argv[0], argv[optind]);
			exit(1);
		}

		altpath = argv[optind];
		optind++;
	}

	/* Load the file contexts configuration and check it. */
	opts[0].value = (ctx_validate ? (char*)1 : NULL);
	opts[1].value = altpath;

	hnd = selabel_open(SELABEL_CTX_FILE, opts, 2);
	if (!hnd) {
		perror(altpath);
		exit(1);
	}

	if (nerr)
		exit(1);

	if (use_input_file) {
		FILE *f = stdin;
		ssize_t len;
		int delim;
		if (strcmp(input_filename, "-") != 0)
			f = fopen(input_filename, "r");
		if (f == NULL) {
			fprintf(stderr, "Unable to open %s: %s\n", input_filename,
				strerror(errno));
			usage(argv[0]);
		}
		__fsetlocking(f, FSETLOCKING_BYCALLER);

		delim = (null_terminated != 0) ? '\0' : '\n';
		while ((len = getdelim(&buf, &buf_len, delim, f)) > 0) {
			buf[len - 1] = 0;
			errors |= process_one_realpath(buf);
		}
		if (strcmp(input_filename, "-") != 0)
			fclose(f);
	} else {
		for (i = optind; i < argc; i++) {
			errors |= process_one_realpath(argv[i]);
		}
	}

	maybe_audit_mass_relabel();

	if (warn_no_match)
		selabel_stats(hnd);

	selabel_close(hnd);

	if (outfile)
		fclose(outfile);

	for (i = 0; i < excludeCtr; i++) {
		free(excludeArray[i].directory);
	}

       if (progress && count >= STAR_COUNT)
               printf("\n");
	exit(errors);
}
