/*
 * The majority of this code is from Android's
 * external/libselinux/src/android.c and upstream
 * selinux/policycoreutils/setfiles/restore.c
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
#include <dirent.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <sys/vfs.h>
#include <sys/statvfs.h>
#include <sys/utsname.h>
#include <linux/magic.h>
#include <libgen.h>
#include <syslog.h>
#include <assert.h>

#include <selinux/selinux.h>
#include <selinux/context.h>
#include <selinux/label.h>
#include <selinux/restorecon.h>

#include "callbacks.h"
#include "selinux_internal.h"
#include "label_file.h"
#include "sha1.h"

static struct selabel_handle *fc_sehandle = NULL;
static bool selabel_no_digest;
static char *rootpath = NULL;
static size_t rootpathlen;

/* Information on excluded fs and directories. */
struct edir {
	char *directory;
	size_t size;
	/* True if excluded by selinux_restorecon_set_exclude_list(3). */
	bool caller_excluded;
};
#define CALLER_EXCLUDED true
static bool ignore_mounts;
static uint64_t exclude_non_seclabel_mounts(void);
static int exclude_count = 0;
static struct edir *exclude_lst = NULL;
static uint64_t fc_count = 0; /* Number of files processed so far */
static uint64_t efile_count; /* Estimated total number of files */
static pthread_mutex_t progress_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Store information on directories with xattr's. */
static struct dir_xattr *dir_xattr_list;
static struct dir_xattr *dir_xattr_last;

/* Number of errors ignored during the file tree walk. */
static long unsigned skipped_errors;

/* Number of successfully relabeled files or files that would be relabeled */
static long unsigned relabeled_files;

/* restorecon_flags for passing to restorecon_sb() */
struct rest_flags {
	bool nochange;
	bool verbose;
	bool progress;
	bool mass_relabel;
	bool set_specctx;
	bool set_user_role;
	bool add_assoc;
	bool recurse;
	bool userealpath;
	bool set_xdev;
	bool abort_on_error;
	bool syslog_changes;
	bool log_matches;
	bool ignore_noent;
	bool warnonnomatch;
	bool conflicterror;
	bool count_errors;
	bool count_relabeled;
	bool skip_multilink;
};

static bool have_proc;

static bool probe_proc(void)
{
	struct statfs sb;

	if (statfs("/proc", &sb) < 0)
		return false;
	if (sb.f_type != PROC_SUPER_MAGIC)
		return false;
	return true;
}

static int fd_path_getfilecon(int fd, const char *pathname, char **con)
{
	char proc_path[32];
	int rc;

	if (have_proc) {
		rc = snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d",
			      fd);
		if (rc < 0 || (size_t)rc >= sizeof(proc_path))
			return -1;
		return getfilecon_raw(proc_path, con);
	}

	return lgetfilecon_raw(pathname, con);
}

static int fd_path_setfilecon(int fd, const char *pathname, char *con)
{
	char proc_path[32];
	int rc;

	if (have_proc) {
		rc = snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d",
			      fd);
		if (rc < 0 || (size_t)rc >= sizeof(proc_path))
			return -1;
		return setfilecon_raw(proc_path, con);
	}

	return lsetfilecon_raw(pathname, con);
}

static void restorecon_init(void)
{
	struct selabel_handle *sehandle = NULL;

	if (!fc_sehandle) {
		sehandle = selinux_restorecon_default_handle();
		selinux_restorecon_set_sehandle(sehandle);
	}

	efile_count = 0;
	if (!ignore_mounts)
		efile_count = exclude_non_seclabel_mounts();

	have_proc = probe_proc();
}

static pthread_once_t fc_once = PTHREAD_ONCE_INIT;

/*
 * Manage excluded directories:
 *  remove_exclude() - This removes any conflicting entries as there could be
 *                     a case where a non-seclabel fs is mounted on /foo and
 *                     then a seclabel fs is mounted on top of it.
 *                     However if an entry has been added via
 *                     selinux_restorecon_set_exclude_list(3) do not remove.
 *
 *  add_exclude()    - Add a directory/fs to be excluded from labeling. If it
 *                     has already been added, then ignore.
 *
 *  check_excluded() - Check if directory/fs is to be excluded when relabeling.
 *
 *  file_system_count() - Calculates the number of files to be processed.
 *                        The count is only used if SELINUX_RESTORECON_PROGRESS
 *                        is set and a mass relabel is requested.
 *
 *  exclude_non_seclabel_mounts() - Reads /proc/mounts to determine what
 *                                  non-seclabel mounts to exclude from
 *                                  relabeling. restorecon_init() will not
 *                                  call this function if the
 *                                  SELINUX_RESTORECON_IGNORE_MOUNTS
 *                                  flag is set.
 *                                  Setting SELINUX_RESTORECON_IGNORE_MOUNTS
 *                                  is useful where there is a non-seclabel fs
 *                                  mounted on /foo and then a seclabel fs is
 *                                  mounted on a directory below this.
 */
static void remove_exclude(const char *directory)
{
	int i;

	for (i = 0; i < exclude_count; i++) {
		if (strcmp(directory, exclude_lst[i].directory) == 0 &&
		    !exclude_lst[i].caller_excluded) {
			free(exclude_lst[i].directory);
			if (i != exclude_count - 1)
				exclude_lst[i] = exclude_lst[exclude_count - 1];
			exclude_count--;
			return;
		}
	}
}

static int add_exclude(const char *directory, bool who)
{
	struct edir *tmp_list, *current;
	size_t len = 0;
	int i;

	if (directory == NULL || directory[0] != '/') {
		selinux_log(SELINUX_ERROR,
			    "Full path required for exclude: %s.\n", directory);
		errno = EINVAL;
		return -1;
	}

	/* Check if already present. */
	for (i = 0; i < exclude_count; i++) {
		if (strcmp(directory, exclude_lst[i].directory) == 0)
			return 0;
	}

	if (exclude_count >= INT_MAX - 1) {
		selinux_log(SELINUX_ERROR, "Too many directory excludes: %d.\n",
			    exclude_count);
		errno = EOVERFLOW;
		return -1;
	}

	tmp_list = reallocarray(exclude_lst, exclude_count + 1,
				sizeof(struct edir));
	if (!tmp_list)
		goto oom;

	exclude_lst = tmp_list;

	len = strlen(directory);
	while (len > 1 && directory[len - 1] == '/')
		len--;

	current = (exclude_lst + exclude_count);

	current->directory = strndup(directory, len);
	if (!current->directory)
		goto oom;

	current->size = len;
	current->caller_excluded = who;
	exclude_count++;
	return 0;

oom:
	selinux_log(SELINUX_ERROR, "%s:  Out of memory\n", __func__);
	return -1;
}

static int check_excluded(const char *file)
{
	int i;

	for (i = 0; i < exclude_count; i++) {
		if (strncmp(file, exclude_lst[i].directory,
			    exclude_lst[i].size) == 0) {
			if (file[exclude_lst[i].size] == 0 ||
			    file[exclude_lst[i].size] == '/')
				return 1;
		}
	}
	return 0;
}

static uint64_t file_system_count(const char *name)
{
	struct statvfs statvfs_buf;
	uint64_t nfile = 0;

	memset(&statvfs_buf, 0, sizeof(statvfs_buf));
	if (!statvfs(name, &statvfs_buf))
		nfile = statvfs_buf.f_files - statvfs_buf.f_ffree;

	return nfile;
}

/*
 * This is called once when selinux_restorecon() is first called.
 * Searches /proc/mounts for all file systems that do not support extended
 * attributes and adds them to the exclude directory table.  File systems
 * that support security labels have the seclabel option, return
 * approximate total file count.
 */
static uint64_t exclude_non_seclabel_mounts(void)
{
	struct utsname uts;
	FILE *fp;
	size_t len;
	int index = 0, found = 0;
	uint64_t nfile = 0;
	char *mount_info[4];
	char *buf = NULL, *item, *saveptr;

	/* Check to see if the kernel supports seclabel */
	if (uname(&uts) == 0 && strverscmp(uts.release, "2.6.30") < 0)
		return 0;
	if (is_selinux_enabled() <= 0)
		return 0;

	fp = fopen("/proc/mounts", "re");
	if (!fp)
		return 0;

	while (getline(&buf, &len, fp) != -1) {
		found = 0;
		index = 0;
		saveptr = NULL;
		item = strtok_r(buf, " ", &saveptr);
		while (item != NULL) {
			mount_info[index] = item;
			index++;
			if (index == 4)
				break;
			item = strtok_r(NULL, " ", &saveptr);
		}
		if (index < 4) {
			selinux_log(
				SELINUX_ERROR,
				"/proc/mounts record \"%s\" has incorrect format.\n",
				buf);
			continue;
		}

		/* Remove pre-existing entry */
		remove_exclude(mount_info[1]);

		saveptr = NULL;
		item = strtok_r(mount_info[3], ",", &saveptr);
		while (item != NULL) {
			if (strcmp(item, "seclabel") == 0) {
				found = 1;
				nfile += file_system_count(mount_info[1]);
				break;
			}
			item = strtok_r(NULL, ",", &saveptr);
		}

		/* Exclude mount points without the seclabel option */
		if (!found) {
			if (add_exclude(mount_info[1], !CALLER_EXCLUDED) &&
			    errno == ENOMEM)
				assert(0);
		}
	}

	free(buf);
	fclose(fp);
	/* return estimated #Files + 5% for directories and hard links */
	return nfile * 1.05;
}

/* Called by selinux_restorecon_xattr(3) to build a linked list of entries. */
static int add_xattr_entry(const char *directory, bool delete_nonmatch,
			   bool delete_all)
{
	char *sha1_buf = NULL;
	size_t i, digest_len = 0;
	int rc;
	enum digest_result digest_result;
	bool match;
	struct dir_xattr *new_entry;
	uint8_t *xattr_digest = NULL;
	uint8_t *calculated_digest = NULL;

	if (!directory) {
		errno = EINVAL;
		return -1;
	}

	match = selabel_get_digests_all_partial_matches(fc_sehandle, directory,
							&calculated_digest,
							&xattr_digest,
							&digest_len);

	if (!xattr_digest || !digest_len) {
		free(calculated_digest);
		return 1;
	}

	/* Convert entry to a hex encoded string. */
	sha1_buf = malloc(digest_len * 2 + 1);
	if (!sha1_buf) {
		free(xattr_digest);
		free(calculated_digest);
		goto oom;
	}

	for (i = 0; i < digest_len; i++)
		sprintf((&sha1_buf[i * 2]), "%02x", xattr_digest[i]);

	digest_result = match ? MATCH : NOMATCH;

	if ((delete_nonmatch && !match) || delete_all) {
		digest_result = match ? DELETED_MATCH : DELETED_NOMATCH;
		rc = removexattr(directory, RESTORECON_PARTIAL_MATCH_DIGEST);
		if (rc) {
			selinux_log(
				SELINUX_ERROR,
				"Error: %m removing xattr \"%s\" from: %s\n",
				RESTORECON_PARTIAL_MATCH_DIGEST, directory);
			digest_result = ERROR;
		}
	}
	free(xattr_digest);
	free(calculated_digest);

	/* Now add entries to link list. */
	new_entry = malloc(sizeof(struct dir_xattr));
	if (!new_entry) {
		free(sha1_buf);
		goto oom;
	}
	new_entry->next = NULL;

	new_entry->directory = strdup(directory);
	if (!new_entry->directory) {
		free(new_entry);
		free(sha1_buf);
		goto oom;
	}

	new_entry->digest = sha1_buf;

	new_entry->result = digest_result;

	if (!dir_xattr_list) {
		dir_xattr_list = new_entry;
		dir_xattr_last = new_entry;
	} else {
		dir_xattr_last->next = new_entry;
		dir_xattr_last = new_entry;
	}

	return 0;

oom:
	selinux_log(SELINUX_ERROR, "%s:  Out of memory\n", __func__);
	return -1;
}

/*
 * Support filespec services filespec_add(), filespec_eval() and
 * filespec_destroy().
 *
 * selinux_restorecon(3) uses filespec services when the
 * SELINUX_RESTORECON_ADD_ASSOC flag is set for adding associations between
 * an inode and a specification.
 */

/*
 * The hash table of associations, hashed by inode number. Chaining is used
 * for collisions, with elements ordered by inode number in each bucket.
 * Each hash bucket has a dummy header.
 */
#define HASH_BITS 16
#define HASH_BUCKETS (1 << HASH_BITS)
#define HASH_MASK (HASH_BUCKETS - 1)

/*
 * An association between an inode and a context.
 */
typedef struct file_spec {
	ino_t ino; /* inode number */
	char *con; /* matched context */
	char *file; /* full pathname */
	struct file_spec *next; /* next association in hash bucket chain */
} file_spec_t;

static file_spec_t *fl_head;
static pthread_mutex_t fl_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * Try to add an association between an inode and a context. If there is a
 * different context that matched the inode, then use the first context
 * that matched.
 */
static int filespec_add(ino_t ino, const char *con, const char *file,
			const struct rest_flags *flags)
{
	file_spec_t *prevfl, *fl;
	uint32_t h;
	int ret;
	struct stat sb;

	__pthread_mutex_lock(&fl_mutex);

	if (!fl_head) {
		fl_head = calloc(HASH_BUCKETS, sizeof(file_spec_t));
		if (!fl_head)
			goto oom;
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
				goto unlock_1;
			}

			if (strcmp(fl->con, con) == 0)
				goto unlock_1;

			selinux_log(
				SELINUX_ERROR,
				"conflicting specifications for %s and %s, using %s.\n",
				file, fl->file, fl->con);
			free(fl->file);
			fl->file = strdup(file);
			if (!fl->file)
				goto oom;

			__pthread_mutex_unlock(&fl_mutex);

			if (flags->conflicterror) {
				selinux_log(
					SELINUX_ERROR,
					"treating conflicting specifications as an error.\n");
				return -1;
			}
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
		goto oom_freeflcon;
	fl->next = prevfl->next;
	prevfl->next = fl;

	__pthread_mutex_unlock(&fl_mutex);
	return 0;

oom_freeflcon:
	free(fl->con);
oom_freefl:
	free(fl);
oom:
	__pthread_mutex_unlock(&fl_mutex);
	selinux_log(SELINUX_ERROR, "%s:  Out of memory\n", __func__);
	return -1;
unlock_1:
	__pthread_mutex_unlock(&fl_mutex);
	return 1;
}

/*
 * Evaluate the association hash table distribution.
 */
#ifdef DEBUG
static void filespec_eval(void)
{
	file_spec_t *fl;
	uint32_t h;
	size_t used, nel, len, longest;

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

	selinux_log(
		SELINUX_INFO,
		"filespec hash table stats: %zu elements, %zu/%zu buckets used, longest chain length %zu\n",
		nel, used, HASH_BUCKETS, longest);
}
#else
static void filespec_eval(void)
{
}
#endif

/*
 * Destroy the association hash table.
 */
static void filespec_destroy(void)
{
	file_spec_t *fl, *tmp;
	uint32_t h;

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
 * Also update user and role components if
 * SELINUX_RESTORECON_SET_USER_ROLE is set.
 */
static int compare_portions(const char *curcon, const char *newcon,
			    bool set_user_role, char **newtypecon)
{
	context_t curctx;
	context_t newctx;
	bool update = false;
	int rc = 0;

	curctx = context_new(curcon);
	if (!curctx) {
		rc = -1;
		goto out;
	}
	newctx = context_new(newcon);
	if (!newctx) {
		context_free(curctx);
		rc = -1;
		goto out;
	}

	if (strcmp(context_type_get(curctx), context_type_get(newctx)) != 0) {
		update = true;
		rc = context_type_set(curctx, context_type_get(newctx));
		if (rc)
			goto err;
	}

	if (set_user_role) {
		if (strcmp(context_user_get(curctx),
			   context_user_get(newctx)) != 0) {
			update = true;
			rc = context_user_set(curctx, context_user_get(newctx));
			if (rc)
				goto err;
		}

		if (strcmp(context_role_get(curctx),
			   context_role_get(newctx)) != 0) {
			update = true;
			rc = context_role_set(curctx, context_role_get(newctx));
			if (rc)
				goto err;
		}
	}

	if (update) {
		*newtypecon = context_to_str(curctx);
		if (!*newtypecon) {
			rc = -1;
			goto err;
		}
	} else {
		*newtypecon = NULL;
	}

err:
	context_free(curctx);
	context_free(newctx);
out:
	return rc;
}

static int restorecon_sb(int fd, const char *pathname, const struct stat *sb,
			 const struct rest_flags *flags, bool first,
			 bool *updated_out)
{
	char *newcon = NULL;
	char *curcon = NULL;
	int rc;
	bool updated = false;
	const char *lookup_path = pathname;

	if (flags->skip_multilink && !S_ISDIR(sb->st_mode) &&
	    sb->st_nlink > 1) {
		selinux_log(SELINUX_INFO,
			    "Skipping %s: file has multiple links\n", pathname);
		return 0;
	}

	if (rootpath) {
		if (strncmp(rootpath, lookup_path, rootpathlen) != 0) {
			selinux_log(SELINUX_ERROR,
				    "%s is not located in alt_rootpath %s\n",
				    lookup_path, rootpath);
			return -1;
		}
		lookup_path += rootpathlen;
	}

	if (rootpath != NULL && lookup_path[0] == '\0')
		/* this is actually the root dir of the alt root. */
		rc = selabel_lookup_raw(fc_sehandle, &newcon, "/",
					sb->st_mode & S_IFMT);
	else
		rc = selabel_lookup_raw(fc_sehandle, &newcon, lookup_path,
					sb->st_mode & S_IFMT);

	if (rc < 0) {
		if (errno == ENOENT) {
			if (flags->warnonnomatch && first)
				selinux_log(SELINUX_INFO,
					    "Warning no default label for %s\n",
					    lookup_path);

			return 0; /* no match, but not an error */
		}

		return -1;
	}

	if (flags->progress) {
		const unsigned STAR_COUNT = 1024;
		uint64_t fc_count_local;

		fc_count_local =
			__atomic_add_fetch(&fc_count, 1, __ATOMIC_RELAXED);

		if (fc_count_local % STAR_COUNT == 0) {
			__pthread_mutex_lock(&progress_mutex);
			if (flags->mass_relabel && efile_count > 0) {
				float pc = (fc_count_local < efile_count) ?
						   (100.0 * fc_count_local /
						    efile_count) :
						   100;
				fprintf(stdout, "\r%-.1f%%", (double)pc);
			} else {
				fprintf(stdout, "\r%" PRIu64 "k",
					fc_count_local / STAR_COUNT);
			}
			fflush(stdout);
			__pthread_mutex_unlock(&progress_mutex);
		}
	}

	if (flags->add_assoc) {
		rc = filespec_add(sb->st_ino, newcon, pathname, flags);

		if (rc < 0) {
			selinux_log(SELINUX_ERROR, "filespec_add error: %s\n",
				    pathname);
			freecon(newcon);
			return -1;
		}

		if (rc > 0) {
			/* Already an association and it took precedence. */
			freecon(newcon);
			return 0;
		}
	}

	if (flags->log_matches)
		selinux_log(SELINUX_INFO, "%s matched by %s\n", pathname,
			    newcon);

	if (fd_path_getfilecon(fd, pathname, &curcon) < 0) {
		/* Ignore files removed during relabeling if ignore_noent is set */
		if (flags->ignore_noent && errno == ENOENT)
			goto out;
		if (errno != ENODATA)
			goto err;

		curcon = NULL;
	}

	if (curcon == NULL || strcmp(curcon, newcon) != 0) {
		if (!flags->set_specctx && curcon &&
		    (is_context_customizable(curcon) > 0)) {
			if (flags->verbose) {
				selinux_log(
					SELINUX_INFO,
					"%s not reset as customized by admin to %s\n",
					pathname, curcon);
			}
			goto out;
		}

		if (!flags->set_specctx && curcon) {
			char *newtypecon;

			/* If types are different then update newcon.
			 * Also update if SELINUX_RESTORECON_SET_USER_ROLE
			 * is set and user or role differs.
			 */
			rc = compare_portions(curcon, newcon,
					      flags->set_user_role,
					      &newtypecon);
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
			if (fd_path_setfilecon(fd, pathname, newcon) < 0) {
				/* Ignore files removed during relabeling if ignore_noent is set */
				if (flags->ignore_noent && errno == ENOENT) {
					goto out;
				} else if (errno == EROFS) {
					selinux_log(
						SELINUX_INFO,
						"Read only filesystem, relabel not possible: %s\n",
						pathname);
					goto out;
				} else {
					goto err;
				}
			}

			updated = true;
		}

		if (flags->verbose)
			selinux_log(SELINUX_INFO, "%s %s from %s to %s\n",
				    updated ? "Relabeled" : "Would relabel",
				    pathname, curcon ? curcon : "<no context>",
				    newcon);

		if (flags->syslog_changes && !flags->nochange) {
			if (curcon)
				syslog(LOG_INFO,
				       "relabeling %s from %s to %s\n",
				       pathname, curcon, newcon);
			else
				syslog(LOG_INFO, "labeling %s to %s\n",
				       pathname, newcon);
		}

		/* Note: relabel counting handled by caller */
	}

out:
	if (updated_out)
		*updated_out = updated;
	rc = 0;
out1:
	freecon(curcon);
	freecon(newcon);
	return rc;
err:
	selinux_log(SELINUX_ERROR, "Could not set context for %s:  %m\n",
		    pathname);
	rc = -1;
	goto out1;
}

/*
 * Returns true if the digest of all partial matched contexts is the same as
 * the one saved by setxattr. Otherwise returns false and sets @have_digest
 * to indicate if @digest_out was set to the digest to apply after
 * relabeling this directory.
 */
static bool check_context_match_for_dir(const char *pathname,
					uint8_t digest_out[SHA1_HASH_SIZE],
					bool *have_digest)
{
	bool status;
	size_t digest_len = 0;
	uint8_t *read_digest = NULL;
	uint8_t *calculated_digest = NULL;

	*have_digest = false;

	/* status = true if digests match, false otherwise. */
	status = selabel_get_digests_all_partial_matches(fc_sehandle, pathname,
							 &calculated_digest,
							 &read_digest,
							 &digest_len);
	if (status)
		goto free;

	/* Save digest of all matched contexts for the current directory. */
	if (calculated_digest) {
		assert(digest_len == SHA1_HASH_SIZE);
		memcpy(digest_out, calculated_digest, SHA1_HASH_SIZE);
		*have_digest = true;
	}

free:
	free(calculated_digest);
	free(read_digest);
	return status;
}

struct walk_level {
	DIR *dirp;
	dev_t dev;
	ino_t ino;
	size_t pathlen;
	uint8_t digest[SHA1_HASH_SIZE];
	bool write_digest;
};

struct rest_state {
	struct rest_flags flags;
	dev_t dev_num;
	struct statfs sfsb;
	bool ignore_digest;
	bool setrestorecondigest;
	bool parallel;

	struct walk_level *stack;
	size_t depth;
	size_t stack_cap;
	char pathbuf[PATH_MAX];

	int root_fd;
	struct stat root_sb;

	bool abort;
	int error;
	long unsigned skipped_errors;
	long unsigned relabeled_files;
	int saved_errno;
	pthread_mutex_t mutex;
};

static int walk_push(struct rest_state *st, int rdfd, dev_t dev, ino_t ino,
		     size_t pathlen)
{
	struct walk_level *wl;
	DIR *dirp;

	if (st->depth == st->stack_cap) {
		size_t ncap = st->stack_cap ? st->stack_cap * 2 : 16;
		struct walk_level *n =
			reallocarray(st->stack, ncap, sizeof(*st->stack));
		if (!n) {
			close(rdfd);
			return -1;
		}
		st->stack = n;
		st->stack_cap = ncap;
	}

	dirp = fdopendir(rdfd);
	if (!dirp) {
		close(rdfd);
		return -1;
	}

	wl = &st->stack[st->depth];
	wl->dirp = dirp;
	wl->dev = dev;
	wl->ino = ino;
	wl->pathlen = pathlen;
	wl->write_digest = false;
	st->depth++;
	return 0;
}

static inline void prune_pathbuf(struct rest_state *st)
{
	if (st->depth)
		st->pathbuf[st->stack[st->depth - 1].pathlen] = '\0';
}

static void walk_pop(struct rest_state *st)
{
	if (st->depth == 0)
		return;
	st->depth--;
	closedir(st->stack[st->depth].dirp);
	prune_pathbuf(st);
}

static void walk_free(struct rest_state *st)
{
	while (st->depth)
		walk_pop(st);
	free(st->stack);
	st->stack = NULL;
	st->stack_cap = 0;
}

static size_t walk_path_append(struct rest_state *st, const char *name)
{
	size_t base = st->stack[st->depth - 1].pathlen;
	size_t nlen = strlen(name);
	bool need_slash = (base > 0 && st->pathbuf[base - 1] != '/');
	size_t total = base + (need_slash ? 1 : 0) + nlen;

	if (total >= sizeof(st->pathbuf))
		return (size_t)-1;

	if (need_slash)
		st->pathbuf[base++] = '/';
	memcpy(st->pathbuf + base, name, nlen);
	st->pathbuf[base + nlen] = '\0';
	return base + nlen;
}

static bool walk_is_cycle(const struct rest_state *st, dev_t dev, ino_t ino)
{
	for (size_t i = 0; i < st->depth; i++)
		if (st->stack[i].dev == dev && st->stack[i].ino == ino)
			return true;
	return false;
}

static bool note_walk_error(struct rest_state *state)
{
	if (state->flags.abort_on_error) {
		state->error = -1;
		state->abort = true;
		return true;
	}
	if (state->flags.count_errors)
		state->skipped_errors++;
	else
		state->error = -1;
	return false;
}

/*
 * Map a dirent d_type to the matching S_IF* file-type bits, or 0 if d_type
 * is not informative (e.g. DT_UNKNOWN on filesystems that do not fill it in).
 */
static mode_t d_type_to_mode(unsigned char d_type)
{
	switch (d_type) {
	case DT_REG:
		return S_IFREG;
	case DT_DIR:
		return S_IFDIR;
	case DT_LNK:
		return S_IFLNK;
	case DT_FIFO:
		return S_IFIFO;
	case DT_SOCK:
		return S_IFSOCK;
	case DT_BLK:
		return S_IFBLK;
	case DT_CHR:
		return S_IFCHR;
	default:
		return 0;
	}
}

static int open_final(int dfd, const char *name, struct stat *sb)
{
	int fd;

	if (name)
		fd = openat(dfd, name, O_PATH | O_NOFOLLOW | O_CLOEXEC);
	else
		fd = fcntl(dfd, F_DUPFD_CLOEXEC, 0);
	if (fd < 0)
		return -1;

	if (fstat(fd, sb) < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

static int safe_open(const char *path, struct stat *sb)
{
	char *copy, *cur, *slash;
	int dfd, nfd;

	if (!path || path[0] == '\0') {
		errno = ENOENT;
		return -1;
	}

	copy = strdup(path);
	if (!copy)
		return -1;

	if (copy[0] == '/') {
		dfd = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC);
		cur = copy + 1;
	} else {
		dfd = open(".", O_PATH | O_DIRECTORY | O_CLOEXEC);
		cur = copy;
	}
	if (dfd < 0) {
		free(copy);
		return -1;
	}

	while (*cur == '/')
		cur++;

	while (*cur != '\0') {
		slash = strchr(cur, '/');
		if (slash) {
			*slash = '\0';
			char *next = slash + 1;
			while (*next == '/')
				next++;
			if (*next != '\0') {
				nfd = openat(dfd, cur,
					     O_PATH | O_NOFOLLOW | O_DIRECTORY |
						     O_CLOEXEC);
				close(dfd);
				if (nfd < 0) {
					free(copy);
					return -1;
				}
				dfd = nfd;
				cur = next;
				continue;
			}
		}

		nfd = open_final(dfd, cur, sb);
		close(dfd);
		free(copy);
		return nfd;
	}

	nfd = open_final(dfd, NULL, sb);
	close(dfd);
	free(copy);
	return nfd;
}

/*
 * Returns 1 if we successfully filled ent_* with the next entry
 * to process, 0 on clean end-of-walk, -1 with errno set on
 * fatal failure from readdir() or path too long.
 */
static int walk_next(struct rest_state *state, int *ent_fd, int *rd_fd,
		     struct stat *ent_sb, char *ent_path, size_t ent_path_sz,
		     size_t *ent_pathlen)
{
	if (state->root_fd >= 0) {
		int fd = state->root_fd;

		state->root_fd = -1;
		*ent_fd = fd;
		*ent_sb = state->root_sb;
		*ent_pathlen = strlen(state->pathbuf);
		strlcpy(ent_path, state->pathbuf, ent_path_sz);
		*rd_fd = -1;
		if (S_ISDIR(state->root_sb.st_mode)) {
			*rd_fd = openat(fd, ".",
					O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
						O_CLOEXEC);
			if (*rd_fd < 0 &&
			    (!state->flags.ignore_noent || errno != ENOENT)) {
				selinux_log(SELINUX_ERROR,
					    "Could not read %s: %m\n",
					    state->pathbuf);
				note_walk_error(state);
			}
		}
		return 1;
	}

	while (state->depth) {
		struct walk_level *top = &state->stack[state->depth - 1];
		int pdfd = dirfd(top->dirp);
		struct dirent *de;

		errno = 0;
		de = readdir(top->dirp);
		if (!de) {
			if (errno) {
				selinux_log(
					SELINUX_ERROR,
					"Could not read directory %s: %m.\n",
					state->pathbuf);
				walk_pop(state);
				if (note_walk_error(state))
					return -1;
				continue;
			}
			/*
			 * Completed directory traversal; set digest
			 * if requested and no errors.
			 */
			if (top->write_digest && state->setrestorecondigest &&
			    !state->flags.nochange && !state->error &&
			    !state->skipped_errors &&
			    fsetxattr(dirfd(top->dirp),
				      RESTORECON_PARTIAL_MATCH_DIGEST,
				      top->digest, SHA1_HASH_SIZE, 0) < 0) {
				selinux_log(SELINUX_ERROR,
					    "Could not set digest on %s: %m\n",
					    state->pathbuf);
			}
			walk_pop(state);
			continue;
		}

		if (de->d_name[0] == '.' &&
		    (de->d_name[1] == '\0' ||
		     (de->d_name[1] == '.' && de->d_name[2] == '\0')))
			continue;

		size_t plen = walk_path_append(state, de->d_name);
		if (plen == (size_t)-1) {
			selinux_log(
				SELINUX_ERROR,
				"Path name too long under %.*s, skipping.\n",
				(int)top->pathlen, state->pathbuf);
			errno = ENAMETOOLONG;
			if (note_walk_error(state))
				return -1;
			continue;
		}

		int fd = openat(pdfd, de->d_name,
				O_PATH | O_NOFOLLOW | O_CLOEXEC);
		if (fd < 0) {
			if (!state->flags.ignore_noent || errno != ENOENT) {
				selinux_log(SELINUX_ERROR,
					    "Could not open %s: %m.\n",
					    state->pathbuf);
				state->pathbuf[top->pathlen] = '\0';
				if (note_walk_error(state))
					return -1;
				continue;
			}
			state->pathbuf[top->pathlen] = '\0';
			continue;
		}

		/*
		 * Skip fstat() when d_type already gives the file type and
		 * none of xdev (st_dev), add_assoc (st_ino), or
		 * skip_multilink (st_nlink) are needed.
		 * Directories always fstat for cycle detection and walk_push().
		 */
		mode_t mode_from_dtype = d_type_to_mode(de->d_type);
		bool need_fstat =
			mode_from_dtype == 0 || S_ISDIR(mode_from_dtype) ||
			state->flags.set_xdev || state->flags.add_assoc ||
			state->flags.skip_multilink;

		if (need_fstat) {
			if (fstat(fd, ent_sb) < 0) {
				selinux_log(SELINUX_ERROR,
					    "Could not stat %s: %m.\n",
					    state->pathbuf);
				close(fd);
				state->pathbuf[top->pathlen] = '\0';
				if (note_walk_error(state))
					return -1;
				continue;
			}
		} else {
			memset(ent_sb, 0, sizeof(*ent_sb));
			ent_sb->st_mode = mode_from_dtype;
		}

		int rdfd = -1;
		if (S_ISDIR(ent_sb->st_mode)) {
			rdfd = openat(fd, ".",
				      O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
					      O_CLOEXEC);
			if (rdfd < 0 &&
			    (!state->flags.ignore_noent || errno != ENOENT)) {
				selinux_log(SELINUX_ERROR,
					    "Could not open %s: %m.\n",
					    state->pathbuf);
				/*
				 * Even if we cannot open the directory for
				 * reading, we want to relabel the directory
				 * itself.
				 */
				(void)note_walk_error(state);
			}
		}

		strlcpy(ent_path, state->pathbuf, ent_path_sz);
		*ent_pathlen = plen;
		*ent_fd = fd;
		*rd_fd = rdfd;

		if (rdfd < 0)
			state->pathbuf[top->pathlen] = '\0';

		return 1;
	}

	return 0;
}

static void *selinux_restorecon_thread(void *arg)
{
	struct rest_state *state = arg;
	int error, rc;
	int ent_fd, rd_fd;
	struct stat ent_sb;
	size_t ent_pathlen;
	char ent_path[PATH_MAX];
	bool first = false;

	if (state->parallel)
		__pthread_mutex_lock(&state->mutex);

	if (state->root_fd >= 0)
		first = true;

	while ((rc = walk_next(state, &ent_fd, &rd_fd, &ent_sb, ent_path,
			       sizeof(ent_path), &ent_pathlen)) == 1) {
		if (state->abort) {
			close(ent_fd);
			if (rd_fd >= 0)
				close(rd_fd);
			goto unlock;
		}

		bool is_dir = S_ISDIR(ent_sb.st_mode);
		bool descend = (rd_fd >= 0);

		/* Emulate FTS_XDEV behavior */
		if (state->flags.set_xdev && ent_sb.st_dev != state->dev_num) {
			close(ent_fd);
			if (rd_fd >= 0)
				close(rd_fd);
			prune_pathbuf(state);
			continue;
		}

		if (is_dir) {
			if (descend && walk_is_cycle(state, ent_sb.st_dev,
						     ent_sb.st_ino)) {
				selinux_log(SELINUX_ERROR,
					    "Directory cycle on %s.\n",
					    ent_path);
				close(ent_fd);
				close(rd_fd);
				errno = ELOOP;
				state->error = -1;
				state->abort = true;
				goto finish;
			}

			if (state->sfsb.f_type == SYSFS_MAGIC &&
			    !selabel_partial_match(fc_sehandle, ent_path)) {
				close(ent_fd);
				if (rd_fd >= 0)
					close(rd_fd);
				prune_pathbuf(state);
				continue;
			}

			if (check_excluded(ent_path)) {
				close(ent_fd);
				if (rd_fd >= 0)
					close(rd_fd);
				prune_pathbuf(state);
				continue;
			}

			uint8_t digest[SHA1_HASH_SIZE];
			bool have_digest = false;

			if (descend && state->setrestorecondigest &&
			    check_context_match_for_dir(ent_path, digest,
							&have_digest) &&
			    !state->ignore_digest) {
				selinux_log(
					SELINUX_INFO,
					"Skipping restorecon on directory(%s)\n",
					ent_path);
				close(ent_fd);
				close(rd_fd);
				prune_pathbuf(state);
				continue;
			}

			if (descend) {
				if (walk_push(state, rd_fd, ent_sb.st_dev,
					      ent_sb.st_ino, ent_pathlen) < 0) {
					close(ent_fd);
					errno = ENOMEM;
					state->error = -1;
					state->abort = true;
					goto finish;
				}

				if (have_digest) {
					struct walk_level *wl =
						&state->stack[state->depth - 1];

					memcpy(wl->digest, digest,
					       SHA1_HASH_SIZE);
					wl->write_digest = true;
				}
			}
		}

		if (state->parallel)
			__pthread_mutex_unlock(&state->mutex);

		bool updated = false;
		error = restorecon_sb(ent_fd, ent_path, &ent_sb, &state->flags,
				      first, &updated);
		close(ent_fd);

		if (state->parallel) {
			__pthread_mutex_lock(&state->mutex);
			if (state->abort)
				goto unlock;
		}

		first = false;
		if (error) {
			if (state->flags.abort_on_error) {
				state->error = error;
				state->abort = true;
				goto finish;
			}
			if (state->flags.count_errors)
				state->skipped_errors++;
			else
				state->error = error;
		} else if (updated && state->flags.count_relabeled) {
			state->relabeled_files++;
		}
	}

	if (rc < 0) {
		state->error = -1;
		state->abort = true;
	}

finish:
	if (!state->saved_errno)
		state->saved_errno = errno;
unlock:
	if (state->parallel)
		__pthread_mutex_unlock(&state->mutex);
	return NULL;
}

static int selinux_restorecon_common(const char *pathname_orig,
				     unsigned int restorecon_flags,
				     size_t nthreads)
{
	struct rest_state state;
	int top_fd;

	state.flags.nochange =
		(restorecon_flags & SELINUX_RESTORECON_NOCHANGE) ? true : false;
	state.flags.verbose =
		(restorecon_flags & SELINUX_RESTORECON_VERBOSE) ? true : false;
	state.flags.progress =
		(restorecon_flags & SELINUX_RESTORECON_PROGRESS) ? true : false;
	state.flags.mass_relabel =
		(restorecon_flags & SELINUX_RESTORECON_MASS_RELABEL) ? true :
								       false;
	state.flags.recurse =
		(restorecon_flags & SELINUX_RESTORECON_RECURSE) ? true : false;
	state.flags.set_specctx =
		(restorecon_flags & SELINUX_RESTORECON_SET_SPECFILE_CTX) ?
			true :
			false;
	state.flags.set_user_role =
		(restorecon_flags & SELINUX_RESTORECON_SET_USER_ROLE) ? true :
									false;
	state.flags.userealpath =
		(restorecon_flags & SELINUX_RESTORECON_REALPATH) ? true : false;
	state.flags.set_xdev =
		(restorecon_flags & SELINUX_RESTORECON_XDEV) ? true : false;
	state.flags.add_assoc =
		(restorecon_flags & SELINUX_RESTORECON_ADD_ASSOC) ? true :
								    false;
	state.flags.abort_on_error =
		(restorecon_flags & SELINUX_RESTORECON_ABORT_ON_ERROR) ? true :
									 false;
	state.flags.syslog_changes =
		(restorecon_flags & SELINUX_RESTORECON_SYSLOG_CHANGES) ? true :
									 false;
	state.flags.log_matches =
		(restorecon_flags & SELINUX_RESTORECON_LOG_MATCHES) ? true :
								      false;
	state.flags.ignore_noent =
		(restorecon_flags & SELINUX_RESTORECON_IGNORE_NOENTRY) ? true :
									 false;
	state.flags.warnonnomatch = true;
	state.flags.conflicterror =
		(restorecon_flags & SELINUX_RESTORECON_CONFLICT_ERROR) ? true :
									 false;
	ignore_mounts = (restorecon_flags & SELINUX_RESTORECON_IGNORE_MOUNTS) ?
				true :
				false;
	state.ignore_digest =
		(restorecon_flags & SELINUX_RESTORECON_IGNORE_DIGEST) ? true :
									false;
	state.flags.count_errors =
		(restorecon_flags & SELINUX_RESTORECON_COUNT_ERRORS) ? true :
								       false;
	state.flags.count_relabeled =
		(restorecon_flags & SELINUX_RESTORECON_COUNT_RELABELED) ? true :
									  false;
	state.flags.skip_multilink =
		(restorecon_flags & SELINUX_RESTORECON_SKIP_MULTILINK) ? true :
									 false;
	state.setrestorecondigest = true;

	state.abort = false;
	state.error = 0;
	state.skipped_errors = 0;
	state.relabeled_files = 0;
	state.saved_errno = 0;
	state.stack = NULL;
	state.depth = 0;
	state.stack_cap = 0;
	state.root_fd = -1;

	struct stat sb;
	char *pathname = NULL, *pathdnamer = NULL, *pathdname, *pathbname;
	int error;

	fc_count = 0;

	if (state.flags.verbose && state.flags.progress)
		state.flags.verbose = false;

	__selinux_once(fc_once, restorecon_init);

	if (!fc_sehandle)
		return -1;

	/*
	 * If selabel_no_digest = true then no digest has been requested by
	 * an external selabel_open(3) call.
	 */
	if (selabel_no_digest ||
	    (restorecon_flags & SELINUX_RESTORECON_SKIP_DIGEST))
		state.setrestorecondigest = false;

	if (!__pthread_supported) {
		if (nthreads != 1) {
			nthreads = 1;
			selinux_log(
				SELINUX_WARNING,
				"Threading functionality not available, falling back to 1 thread.");
		}
	} else if (nthreads == 0) {
		long nproc = sysconf(_SC_NPROCESSORS_ONLN);

		if (nproc > 0) {
			nthreads = nproc;
		} else {
			nthreads = 1;
			selinux_log(
				SELINUX_WARNING,
				"Unable to detect CPU count, falling back to 1 thread.");
		}
	}

	/*
	 * Convert passed-in pathname to canonical pathname by resolving
	 * realpath of containing dir, then appending last component name.
	 */
	if (state.flags.userealpath) {
		char *basename_cpy = strdup(pathname_orig);
		if (!basename_cpy)
			goto realpatherr;
		pathbname = basename(basename_cpy);
		if (!strcmp(pathbname, "/") || !strcmp(pathbname, ".") ||
		    !strcmp(pathbname, "..")) {
			pathname = realpath(pathname_orig, NULL);
			if (!pathname) {
				free(basename_cpy);
				/* missing parent directory */
				if (state.flags.ignore_noent &&
				    errno == ENOENT) {
					return 0;
				}
				goto realpatherr;
			}
		} else {
			char *dirname_cpy = strdup(pathname_orig);
			if (!dirname_cpy) {
				free(basename_cpy);
				goto realpatherr;
			}
			pathdname = dirname(dirname_cpy);
			pathdnamer = realpath(pathdname, NULL);
			free(dirname_cpy);
			if (!pathdnamer) {
				free(basename_cpy);
				if (state.flags.ignore_noent &&
				    errno == ENOENT) {
					return 0;
				}
				goto realpatherr;
			}
			if (!strcmp(pathdnamer, "/"))
				error = asprintf(&pathname, "/%s", pathbname);
			else
				error = asprintf(&pathname, "%s/%s", pathdnamer,
						 pathbname);
			if (error < 0) {
				free(basename_cpy);
				goto oom;
			}
		}
		free(basename_cpy);
	} else {
		pathname = strdup(pathname_orig);
		if (!pathname)
			goto oom;
	}

	top_fd = safe_open(pathname, &sb);
	if (top_fd < 0) {
		if (state.flags.ignore_noent && errno == ENOENT) {
			free(pathdnamer);
			free(pathname);
			return 0;
		} else {
			selinux_log(SELINUX_ERROR, "open(%s) failed: %m\n",
				    pathname);
			error = -1;
			goto cleanup;
		}
	}

	/* Skip digest if not a directory */
	if (!S_ISDIR(sb.st_mode))
		state.setrestorecondigest = false;

	if (!state.flags.recurse) {
		if (check_excluded(pathname)) {
			close(top_fd);
			error = 0;
			goto cleanup;
		}

		bool updated = false;
		error = restorecon_sb(top_fd, pathname, &sb, &state.flags, true,
				      &updated);
		if (updated && state.flags.count_relabeled) {
			state.relabeled_files++;
		}
		close(top_fd);
		goto cleanup;
	}

	/* Obtain fs type */
	memset(&state.sfsb, 0, sizeof(state.sfsb));
	if (!S_ISLNK(sb.st_mode) && fstatfs(top_fd, &state.sfsb) < 0) {
		selinux_log(SELINUX_ERROR, "statfs(%s) failed: %m\n", pathname);
		error = -1;
		close(top_fd);
		goto cleanup;
	}

	/* Skip digest on in-memory filesystems and /sys */
	if ((uint32_t)state.sfsb.f_type == (uint32_t)RAMFS_MAGIC ||
	    state.sfsb.f_type == TMPFS_MAGIC ||
	    state.sfsb.f_type == SYSFS_MAGIC)
		state.setrestorecondigest = false;

	state.dev_num = sb.st_dev;

	if (strlcpy(state.pathbuf, pathname, sizeof(state.pathbuf)) >=
	    sizeof(state.pathbuf)) {
		selinux_log(SELINUX_ERROR, "Path name too long: %s.\n",
			    pathname);
		close(top_fd);
		errno = ENAMETOOLONG;
		error = -1;
		goto cleanup;
	}
	state.root_fd = top_fd;
	state.root_sb = sb;

	if (nthreads == 1) {
		state.parallel = false;
		selinux_restorecon_thread(&state);
	} else {
		size_t i;
		pthread_t self = pthread_self();
		pthread_t *threads = NULL;

		__pthread_mutex_init(&state.mutex, NULL);

		threads = calloc(nthreads - 1, sizeof(*threads));
		if (!threads)
			goto oom;

		state.parallel = true;
		/*
		 * Start (nthreads - 1) threads - the main thread is going to
		 * take part, too.
		 */
		for (i = 0; i < nthreads - 1; i++) {
			if (pthread_create(&threads[i], NULL,
					   selinux_restorecon_thread, &state)) {
				/*
				 * If any thread fails to be created, just mark
				 * it as such and let the successfully created
				 * threads do the job. In the worst case the
				 * main thread will do everything, but that's
				 * still better than to give up.
				 */
				threads[i] = self;
			}
		}

		/* Let's join in on the fun! */
		selinux_restorecon_thread(&state);

		/* Now wait for all threads to finish. */
		for (i = 0; i < nthreads - 1; i++) {
			/* Skip threads that failed to be created. */
			if (pthread_equal(threads[i], self))
				continue;
			pthread_join(threads[i], NULL);
		}
		free(threads);

		__pthread_mutex_destroy(&state.mutex);
	}

	error = state.error;
	if (state.saved_errno)
		goto out;

	skipped_errors = state.skipped_errors;

out:
	if (state.flags.progress && state.flags.mass_relabel)
		fprintf(stdout, "\r%s 100.0%%\n", pathname);

	errno = state.saved_errno;
cleanup:
	if (state.root_fd >= 0)
		close(state.root_fd);
	walk_free(&state);
	relabeled_files = state.relabeled_files;
	if (state.flags.add_assoc) {
		if (state.flags.verbose)
			filespec_eval();
		filespec_destroy();
	}
	free(pathdnamer);
	free(pathname);
	return error;

oom:
	selinux_log(SELINUX_ERROR, "%s:  Out of memory\n", __func__);
	error = -1;
	goto cleanup;

realpatherr:
	selinux_log(
		SELINUX_ERROR,
		"SELinux: Could not get canonical path for %s restorecon: %m.\n",
		pathname_orig);
	error = -1;
	goto cleanup;
}

/*
 * Public API
 */

/* selinux_restorecon(3) - Main function that is responsible for labeling */
int selinux_restorecon(const char *pathname_orig, unsigned int restorecon_flags)
{
	return selinux_restorecon_common(pathname_orig, restorecon_flags, 1);
}

/* selinux_restorecon_parallel(3) - Parallel version of selinux_restorecon(3) */
int selinux_restorecon_parallel(const char *pathname_orig,
				unsigned int restorecon_flags, size_t nthreads)
{
	return selinux_restorecon_common(pathname_orig, restorecon_flags,
					 nthreads);
}

/* selinux_restorecon_set_sehandle(3) is called to set the global fc handle */
void selinux_restorecon_set_sehandle(struct selabel_handle *hndl)
{
	char **specfiles;
	unsigned char *fc_digest;
	size_t num_specfiles, fc_digest_len;

	if (fc_sehandle) {
		selabel_close(fc_sehandle);
	}

	fc_sehandle = hndl;
	if (!fc_sehandle)
		return;

	/* Check if digest requested in selabel_open(3), if so use it. */
	if (selabel_digest(fc_sehandle, &fc_digest, &fc_digest_len, &specfiles,
			   &num_specfiles) < 0)
		selabel_no_digest = true;
	else
		selabel_no_digest = false;
}

/*
 * selinux_restorecon_default_handle(3) is called to set the global restorecon
 * handle by a process if the default params are required.
 */
struct selabel_handle *selinux_restorecon_default_handle(void)
{
	struct selabel_handle *sehandle;

	struct selinux_opt fc_opts[] = { { SELABEL_OPT_DIGEST, (char *)1 } };

	sehandle = selabel_open(SELABEL_CTX_FILE, fc_opts, 1);

	if (!sehandle) {
		selinux_log(SELINUX_ERROR,
			    "Error obtaining file context handle: %m\n");
		return NULL;
	}

	selabel_no_digest = false;
	return sehandle;
}

/*
 * selinux_restorecon_set_exclude_list(3) is called to add additional entries
 * to be excluded from labeling checks.
 */
void selinux_restorecon_set_exclude_list(const char **exclude_list)
{
	int i;
	struct stat sb;

	for (i = 0; exclude_list[i]; i++) {
		if (lstat(exclude_list[i], &sb) < 0 && errno != EACCES) {
			selinux_log(
				SELINUX_ERROR,
				"lstat error on exclude path \"%s\", %m - ignoring.\n",
				exclude_list[i]);
			break;
		}
		if (add_exclude(exclude_list[i], CALLER_EXCLUDED) &&
		    errno == ENOMEM)
			assert(0);
	}
}

/* selinux_restorecon_set_alt_rootpath(3) sets an alternate rootpath. */
int selinux_restorecon_set_alt_rootpath(const char *alt_rootpath)
{
	size_t len;

	/* This should be NULL on first use */
	if (rootpath)
		free(rootpath);

	rootpath = strdup(alt_rootpath);
	if (!rootpath) {
		selinux_log(SELINUX_ERROR, "%s:  Out of memory\n", __func__);
		return -1;
	}

	/* trim trailing /, if present */
	len = strlen(rootpath);
	while (len && (rootpath[len - 1] == '/'))
		rootpath[--len] = '\0';
	rootpathlen = len;

	return 0;
}

/* selinux_restorecon_xattr(3)
 * Find RESTORECON_PARTIAL_MATCH_DIGEST entries.
 */
int selinux_restorecon_xattr(const char *pathname, unsigned int xattr_flags,
			     struct dir_xattr ***xattr_list)
{
	bool recurse = (xattr_flags & SELINUX_RESTORECON_XATTR_RECURSE) ? true :
									  false;
	bool delete_nonmatch =
		(xattr_flags &
		 SELINUX_RESTORECON_XATTR_DELETE_NONMATCH_DIGESTS) ?
			true :
			false;
	bool delete_all =
		(xattr_flags & SELINUX_RESTORECON_XATTR_DELETE_ALL_DIGESTS) ?
			true :
			false;
	ignore_mounts = (xattr_flags & SELINUX_RESTORECON_XATTR_IGNORE_MOUNTS) ?
				true :
				false;

	int rc, fts_flags;
	struct stat sb;
	struct statfs sfsb;
	struct dir_xattr *current, *next;
	FTS *fts;
	FTSENT *ftsent;
	char *paths[2] = { NULL, NULL };

	__selinux_once(fc_once, restorecon_init);

	if (!fc_sehandle)
		return -1;

	if (lstat(pathname, &sb) < 0) {
		if (errno == ENOENT)
			return 0;

		selinux_log(SELINUX_ERROR, "lstat(%s) failed: %m\n", pathname);
		return -1;
	}

	if (!recurse) {
		if (statfs(pathname, &sfsb) == 0) {
			if ((uint32_t)sfsb.f_type == (uint32_t)RAMFS_MAGIC ||
			    sfsb.f_type == TMPFS_MAGIC)
				return 0;
		}

		if (check_excluded(pathname))
			return 0;

		rc = add_xattr_entry(pathname, delete_nonmatch, delete_all);

		if (!rc && dir_xattr_list)
			*xattr_list = &dir_xattr_list;
		else if (rc == -1)
			return rc;

		return 0;
	}

	paths[0] = (char *)pathname;
	fts_flags = FTS_PHYSICAL | FTS_NOCHDIR;

	fts = fts_open(paths, fts_flags, NULL);
	if (!fts) {
		selinux_log(SELINUX_ERROR, "fts error on %s: %m\n", paths[0]);
		return -1;
	}

	while ((ftsent = fts_read(fts)) != NULL) {
		switch (ftsent->fts_info) {
		case FTS_DP:
			continue;
		case FTS_D:
			if (statfs(ftsent->fts_path, &sfsb) == 0) {
				if ((uint32_t)sfsb.f_type ==
					    (uint32_t)RAMFS_MAGIC ||
				    sfsb.f_type == TMPFS_MAGIC)
					continue;
			}
			if (check_excluded(ftsent->fts_path)) {
				fts_set(fts, ftsent, FTS_SKIP);
				continue;
			}

			rc = add_xattr_entry(ftsent->fts_path, delete_nonmatch,
					     delete_all);
			if (rc == 1)
				continue;
			else if (rc == -1)
				goto cleanup;
			break;
		default:
			break;
		}
	}

	if (dir_xattr_list)
		*xattr_list = &dir_xattr_list;

	(void)fts_close(fts);
	return 0;

cleanup:
	rc = errno;
	(void)fts_close(fts);
	errno = rc;

	/* Free any used memory */
	current = dir_xattr_list;
	while (current) {
		next = current->next;
		free(current->directory);
		free(current->digest);
		free(current);
		current = next;
	}
	dir_xattr_list = NULL;
	dir_xattr_last = NULL;
	return -1;
}

long unsigned selinux_restorecon_get_skipped_errors(void)
{
	return skipped_errors;
}

long unsigned selinux_restorecon_get_relabeled_files(void)
{
	return relabeled_files;
}
