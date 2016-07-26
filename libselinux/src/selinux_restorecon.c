/*
 * The majority of this code is from Android's
 * external/libselinux/src/android.c and upstream
 * selinux/policycoreutils/setfiles/restorecon.c
 *
 * See selinux_restorecon(3) for details.
 */

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <fts.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <sys/vfs.h>
#include <linux/magic.h>
#include <libgen.h>
#include <selinux/selinux.h>
#include <selinux/context.h>
#include <selinux/label.h>
#include <selinux/restorecon.h>

#include "callbacks.h"
#include "selinux_internal.h"

#define RESTORECON_LAST "security.restorecon_last"

#define SYS_PATH "/sys"
#define SYS_PREFIX SYS_PATH "/"

static struct selabel_handle *fc_sehandle = NULL;
static unsigned char *fc_digest = NULL;
static size_t fc_digest_len = 0;
static const char **fc_exclude_list = NULL;
static size_t fc_count = 0;
#define STAR_COUNT 1000

/* restorecon_flags for passing to restorecon_sb() */
struct rest_flags {
	bool nochange;
	bool verbose;
	bool progress;
	bool set_specctx;
	bool add_assoc;
	bool ignore_digest;
	bool recurse;
	bool userealpath;
	bool set_xdev;
};

static void restorecon_init(void)
{
	struct selabel_handle *sehandle = NULL;

	if (!fc_sehandle) {
		sehandle = selinux_restorecon_default_handle();
		selinux_restorecon_set_sehandle(sehandle);
	}
}

static pthread_once_t fc_once = PTHREAD_ONCE_INIT;


static int check_excluded(const char *file)
{
	int i;

	for (i = 0; fc_exclude_list[i]; i++) {
		if (strcmp(file, fc_exclude_list[i]) == 0)
				return 1;
	}
	return 0;
}

/*
 * Support filespec services. selinux_restorecon(3) uses filespec services
 * when the SELINUX_RESTORECON_ADD_ASSOC flag is set for adding associations
 * between an inode and a context.
 */

/*
 * The hash table of associations, hashed by inode number. Chaining is used
 * for collisions, with elements ordered by inode number in each bucket.
 * Each hash bucket has a dummy header.
 */
#define HASH_BITS 16
#define HASH_BUCKETS (1 << HASH_BITS)
#define HASH_MASK (HASH_BUCKETS-1)

/*
 * An association between an inode and a context.
 */
typedef struct file_spec {
	ino_t ino;		/* inode number */
	char *con;		/* matched context */
	char *file;		/* full pathname */
	struct file_spec *next;	/* next association in hash bucket chain */
} file_spec_t;

static file_spec_t *fl_head;

/*
 * Try to add an association between an inode and a context. If there is a
 * different context that matched the inode, then use the first context
 * that matched.
 */
static int filespec_add(ino_t ino, const char *con, const char *file)
{
	file_spec_t *prevfl, *fl;
	int h, ret;
	struct stat64 sb;

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
			ret = lstat64(fl->file, &sb);
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

			selinux_log(SELINUX_ERROR,
				"conflicting specifications for %s and %s, using %s.\n",
				file, fl->file, fl->con);
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
	selinux_log(SELINUX_ERROR, "%s:  Out of memory\n", __func__);
	return -1;
}

/*
 * Evaluate the association hash table distribution.
 */
static void filespec_eval(void)
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
		for (fl = fl_head[h].next; fl; fl = fl->next)
			len++;
		if (len)
			used++;
		if (len > longest)
			longest = len;
		nel += len;
	}

	selinux_log(SELINUX_INFO,
		     "filespec hash table stats: %d elements, %d/%d buckets used, longest chain length %d\n",
		     nel, used, HASH_BUCKETS, longest);
}

/*
 * Destroy the association hash table.
 */
static void filespec_destroy(void)
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

/*
 * Called if SELINUX_RESTORECON_SET_SPECFILE_CTX is not set to check if
 * the type components differ, updating newtypecon if so.
 */
static int compare_types(char *curcon, char *newcon, char **newtypecon)
{
	int types_differ = 0;
	context_t cona;
	context_t conb;
	int rc = 0;

	cona = context_new(curcon);
	if (!cona) {
		rc = -1;
		goto out;
	}
	conb = context_new(newcon);
	if (!conb) {
		context_free(cona);
		rc = -1;
		goto out;
	}

	types_differ = strcmp(context_type_get(cona), context_type_get(conb));
	if (types_differ) {
		rc |= context_user_set(conb, context_user_get(cona));
		rc |= context_role_set(conb, context_role_get(cona));
		rc |= context_range_set(conb, context_range_get(cona));
		if (!rc) {
			*newtypecon = strdup(context_str(conb));
			if (!*newtypecon) {
				rc = -1;
				goto err;
			}
		}
	}

err:
	context_free(cona);
	context_free(conb);
out:
	return rc;
}

static int restorecon_sb(const char *pathname, const struct stat *sb,
			    struct rest_flags *flags)
{
	char *newcon = NULL;
	char *curcon = NULL;
	char *newtypecon = NULL;
	int rc = 0;
	bool updated = false;

	if (selabel_lookup_raw(fc_sehandle, &newcon, pathname, sb->st_mode) < 0)
		return 0; /* no match, but not an error */

	if (flags->add_assoc) {
		rc = filespec_add(sb->st_ino, newcon, pathname);

		if (rc < 0) {
			selinux_log(SELINUX_ERROR,
				    "filespec_add error: %s\n", pathname);
			freecon(newcon);
			return -1;
		}

		if (rc > 0) {
			/* Already an association and it took precedence. */
			freecon(newcon);
			return 0;
		}
	}

	if (lgetfilecon_raw(pathname, &curcon) < 0) {
		if (errno != ENODATA)
			goto err;

		curcon = NULL;
	}

	if (flags->progress) {
		fc_count++;
		if (fc_count % STAR_COUNT == 0) {
			fprintf(stdout, "*");
			fflush(stdout);
		}
	}

	if (strcmp(curcon, newcon) != 0) {
		if (!flags->set_specctx && curcon &&
				    (is_context_customizable(curcon) > 0)) {
			if (flags->verbose) {
				selinux_log(SELINUX_INFO,
				 "%s not reset as customized by admin to %s\n",
							    pathname, curcon);
				goto out;
			}
		}

		if (!flags->set_specctx && curcon) {
			/* If types different then update newcon. */
			rc = compare_types(curcon, newcon, &newtypecon);
			if (rc)
				goto err;

			if (newtypecon) {
				freecon(newcon);
				newcon = newtypecon;
			} else {
				goto out;
			}
		}

		if (!flags->nochange) {
			if (lsetfilecon(pathname, newcon) < 0)
				goto err;
			updated = true;
		}

		if (flags->verbose)
			selinux_log(SELINUX_INFO,
				    "%s %s from %s to %s\n",
				    updated ? "Relabeled" : "Would relabel",
				    pathname, curcon, newcon);
	}

out:
	rc = 0;
out1:
	freecon(curcon);
	freecon(newcon);
	return rc;
err:
	selinux_log(SELINUX_ERROR,
		    "Could not set context for %s:  %s\n",
		    pathname, strerror(errno));
	rc = -1;
	goto out1;
}

/*
 * Public API
 */

/* selinux_restorecon(3) - Main function that is responsible for labeling */
int selinux_restorecon(const char *pathname_orig,
				    unsigned int restorecon_flags)
{
	struct rest_flags flags;

	flags.ignore_digest = (restorecon_flags &
		    SELINUX_RESTORECON_IGNORE_DIGEST) ? true : false;
	flags.nochange = (restorecon_flags &
		    SELINUX_RESTORECON_NOCHANGE) ? true : false;
	flags.verbose = (restorecon_flags &
		    SELINUX_RESTORECON_VERBOSE) ? true : false;
	flags.progress = (restorecon_flags &
		    SELINUX_RESTORECON_PROGRESS) ? true : false;
	flags.recurse = (restorecon_flags &
		    SELINUX_RESTORECON_RECURSE) ? true : false;
	flags.set_specctx = (restorecon_flags &
		    SELINUX_RESTORECON_SET_SPECFILE_CTX) ? true : false;
	flags.userealpath = (restorecon_flags &
		   SELINUX_RESTORECON_REALPATH) ? true : false;
	flags.set_xdev = (restorecon_flags &
		   SELINUX_RESTORECON_XDEV) ? true : false;
	flags.add_assoc = (restorecon_flags &
		   SELINUX_RESTORECON_ADD_ASSOC) ? true : false;

	bool issys;
	bool setrestoreconlast = true; /* TRUE = set xattr RESTORECON_LAST
					* FALSE = don't use xattr */
	struct stat sb;
	struct statfs sfsb;
	FTS *fts;
	FTSENT *ftsent;
	char *pathname = NULL, *pathdnamer = NULL, *pathdname, *pathbname;
	char *paths[2] = { NULL , NULL };
	int fts_flags;
	int error, sverrno;
	char *xattr_value = NULL;
	ssize_t size;

	if (flags.verbose && flags.progress)
		flags.verbose = false;

	__selinux_once(fc_once, restorecon_init);

	if (!fc_sehandle)
		return -1;

	if (fc_digest_len) {
		xattr_value = malloc(fc_digest_len);
		if (!xattr_value)
			return -1;
	}

	/*
	 * Convert passed-in pathname to canonical pathname by resolving
	 * realpath of containing dir, then appending last component name.
	 */
	if (flags.userealpath) {
		pathbname = basename((char *)pathname_orig);
		if (!strcmp(pathbname, "/") || !strcmp(pathbname, ".") ||
					    !strcmp(pathbname, "..")) {
			pathname = realpath(pathname_orig, NULL);
			if (!pathname)
				goto realpatherr;
		} else {
			pathdname = dirname((char *)pathname_orig);
			pathdnamer = realpath(pathdname, NULL);
			if (!pathdnamer)
				goto realpatherr;
			if (!strcmp(pathdnamer, "/"))
				error = asprintf(&pathname, "/%s", pathbname);
			else
				error = asprintf(&pathname, "%s/%s",
						    pathdnamer, pathbname);
			if (error < 0)
				goto oom;
		}
	} else {
		pathname = strdup(pathname_orig);
		if (!pathname)
			goto oom;
	}

	paths[0] = pathname;
	issys = (!strcmp(pathname, SYS_PATH) ||
			    !strncmp(pathname, SYS_PREFIX,
			    sizeof(SYS_PREFIX) - 1)) ? true : false;

	if (lstat(pathname, &sb) < 0) {
		error = -1;
		goto cleanup;
	}

	/* Ignore restoreconlast if not a directory */
	if ((sb.st_mode & S_IFDIR) != S_IFDIR)
		setrestoreconlast = false;

	if (!flags.recurse) {
		error = restorecon_sb(pathname, &sb, &flags);
		goto cleanup;
	}

	/* Ignore restoreconlast on /sys */
	if (issys)
		setrestoreconlast = false;

	/* Ignore restoreconlast on in-memory filesystems */
	if (statfs(pathname, &sfsb) == 0) {
		if (sfsb.f_type == RAMFS_MAGIC || sfsb.f_type == TMPFS_MAGIC)
			setrestoreconlast = false;
	}

	if (setrestoreconlast) {
		size = getxattr(pathname, RESTORECON_LAST, xattr_value,
							    fc_digest_len);

		if (!flags.ignore_digest && size == fc_digest_len &&
			    memcmp(fc_digest, xattr_value, fc_digest_len)
								    == 0) {
			selinux_log(SELINUX_INFO,
			    "Skipping restorecon as matching digest on: %s\n",
				    pathname);
			error = 0;
			goto cleanup;
		}
	}

	if (flags.set_xdev)
		fts_flags = FTS_PHYSICAL | FTS_NOCHDIR | FTS_XDEV;
	else
		fts_flags = FTS_PHYSICAL | FTS_NOCHDIR;

	fts = fts_open(paths, fts_flags, NULL);
	if (!fts) {
		error = -1;
		goto cleanup;
	}

	error = 0;
	while ((ftsent = fts_read(fts)) != NULL) {
		switch (ftsent->fts_info) {
		case FTS_DC:
			selinux_log(SELINUX_ERROR,
				    "Directory cycle on %s.\n",
				    ftsent->fts_path);
			errno = ELOOP;
			error = -1;
			goto out;
		case FTS_DP:
			continue;
		case FTS_DNR:
			selinux_log(SELINUX_ERROR,
				    "Could not read %s: %s.\n",
				    ftsent->fts_path,
						  strerror(ftsent->fts_errno));
			fts_set(fts, ftsent, FTS_SKIP);
			continue;
		case FTS_NS:
			selinux_log(SELINUX_ERROR,
				    "Could not stat %s: %s.\n",
				    ftsent->fts_path,
						  strerror(ftsent->fts_errno));
			fts_set(fts, ftsent, FTS_SKIP);
			continue;
		case FTS_ERR:
			selinux_log(SELINUX_ERROR,
				    "Error on %s: %s.\n",
				    ftsent->fts_path,
						  strerror(ftsent->fts_errno));
			fts_set(fts, ftsent, FTS_SKIP);
			continue;
		case FTS_D:
			if (issys && !selabel_partial_match(fc_sehandle,
					    ftsent->fts_path)) {
				fts_set(fts, ftsent, FTS_SKIP);
				continue;
			}
			/* fall through */
		default:
			if (fc_exclude_list) {
				if (check_excluded(ftsent->fts_path)) {
					fts_set(fts, ftsent, FTS_SKIP);
					continue;
				}
			}

			error |= restorecon_sb(ftsent->fts_path,
					       ftsent->fts_statp, &flags);
			break;
		}
	}

	/* Labeling successful. Mark the top level directory as completed. */
	if (setrestoreconlast && !flags.nochange && !error) {
		error = setxattr(pathname, RESTORECON_LAST, fc_digest,
						    fc_digest_len, 0);
		if (!error && flags.verbose)
			selinux_log(SELINUX_INFO,
				   "Updated digest for: %s\n", pathname);
	}

out:
	sverrno = errno;
	(void) fts_close(fts);
	errno = sverrno;
cleanup:
	if (flags.add_assoc) {
		if (flags.verbose)
			filespec_eval();
		filespec_destroy();
	}
	free(pathdnamer);
	free(pathname);
	free(xattr_value);
	return error;

oom:
	sverrno = errno;
	selinux_log(SELINUX_ERROR, "%s:  Out of memory\n", __func__);
	errno = sverrno;
	error = -1;
	goto cleanup;

realpatherr:
	sverrno = errno;
	selinux_log(SELINUX_ERROR,
		    "SELinux: Could not get canonical path for %s restorecon: %s.\n",
		    pathname_orig, strerror(errno));
	errno = sverrno;
	error = -1;
	goto cleanup;
}

/* selinux_restorecon_set_sehandle(3) is called to set the global fc handle */
void selinux_restorecon_set_sehandle(struct selabel_handle *hndl)
{
	char **specfiles, *sha1_buf = NULL;
	size_t num_specfiles, i;

	fc_sehandle = (struct selabel_handle *) hndl;

	/* Read digest if requested in selabel_open(3).
	 * If not the set global params. */
	if (selabel_digest(hndl, &fc_digest, &fc_digest_len,
				   &specfiles, &num_specfiles) < 0) {
		fc_digest = NULL;
		fc_digest_len = 0;
		selinux_log(SELINUX_INFO, "Digest not requested.\n");
		return;
	}

	sha1_buf = malloc(fc_digest_len * 2 + 1);
	if (!sha1_buf) {
		selinux_log(SELINUX_ERROR,
			    "Error allocating digest buffer: %s\n",
						    strerror(errno));
		return;
	}

	for (i = 0; i < fc_digest_len; i++)
		sprintf((&sha1_buf[i * 2]), "%02x", fc_digest[i]);

	selinux_log(SELINUX_INFO,
		    "specfiles SHA1 digest: %s\n", sha1_buf);
	selinux_log(SELINUX_INFO,
		    "calculated using the following specfile(s):\n");
	if (specfiles) {
		for (i = 0; i < num_specfiles; i++)
			selinux_log(SELINUX_INFO,
				    "%s\n", specfiles[i]);
	}
	free(sha1_buf);
}

/*
 * selinux_restorecon_default_handle(3) is called to set the global restorecon
 * handle by a process if the default params are required.
 */
struct selabel_handle *selinux_restorecon_default_handle(void)
{
	struct selabel_handle *sehandle;

	struct selinux_opt fc_opts[] = {
		{ SELABEL_OPT_DIGEST, (char *)1 }
	};

	sehandle = selabel_open(SELABEL_CTX_FILE, fc_opts, 1);

	if (!sehandle) {
		selinux_log(SELINUX_ERROR,
			    "Error obtaining file context handle: %s\n",
						    strerror(errno));
		return NULL;
	}

	return sehandle;
}

/*
 * selinux_restorecon_set_exclude_list(3) is called to set a NULL terminated
 * list of files/directories to exclude.
 */
void selinux_restorecon_set_exclude_list(const char **exclude_list)
{
	fc_exclude_list = exclude_list;
}
