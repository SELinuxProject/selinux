#include "restore.h"
#include <glob.h>
#include <selinux/context.h>

#define SKIP -2
#define ERR -1
#define MAX_EXCLUDES 1000

/*
 * The hash table of associations, hashed by inode number.
 * Chaining is used for collisions, with elements ordered
 * by inode number in each bucket.  Each hash bucket has a dummy 
 * header.
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

struct edir {
	char *directory;
	size_t size;
};


static file_spec_t *fl_head;
static int filespec_add(ino_t ino, const security_context_t con, const char *file);
struct restore_opts *r_opts = NULL;
static void filespec_destroy(void);
static void filespec_eval(void);
static int excludeCtr = 0;
static struct edir excludeArray[MAX_EXCLUDES];

void remove_exclude(const char *directory)
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

void restore_init(struct restore_opts *opts)
{	
	r_opts = opts;
	struct selinux_opt selinux_opts[] = {
		{ SELABEL_OPT_VALIDATE, r_opts->selabel_opt_validate },
		{ SELABEL_OPT_PATH, r_opts->selabel_opt_path }
	};
	r_opts->hnd = selabel_open(SELABEL_CTX_FILE, selinux_opts, 2);
	if (!r_opts->hnd) {
		perror(r_opts->selabel_opt_path);
		exit(1);
	}	
}

void restore_finish()
{
	int i;
	for (i = 0; i < excludeCtr; i++) {
		free(excludeArray[i].directory);
	}
}

static int match(const char *name, struct stat *sb, char **con)
{
	if (!(r_opts->hard_links) && !S_ISDIR(sb->st_mode) && (sb->st_nlink > 1)) {
		fprintf(stderr, "Warning! %s refers to a file with more than one hard link, not fixing hard links.\n",
					name);
		return -1;
	}
	
	if (NULL != r_opts->rootpath) {
		if (0 != strncmp(r_opts->rootpath, name, r_opts->rootpathlen)) {
			fprintf(stderr, "%s:  %s is not located in %s\n",
				r_opts->progname, name, r_opts->rootpath);
			return -1;
		}
		name += r_opts->rootpathlen;
	}

	if (r_opts->rootpath != NULL && name[0] == '\0')
		/* this is actually the root dir of the alt root */
		return selabel_lookup_raw(r_opts->hnd, con, "/", sb->st_mode);
	else
		return selabel_lookup_raw(r_opts->hnd, con, name, sb->st_mode);
}
static int restore(FTSENT *ftsent, int recurse)
{
	char *my_file = strdupa(ftsent->fts_path);
	int ret = -1;
	security_context_t curcon = NULL, newcon = NULL;
	float progress;
	if (match(my_file, ftsent->fts_statp, &newcon) < 0) {
		if ((errno == ENOENT) && ((!recurse) || (r_opts->verbose)))
			fprintf(stderr, "%s:  Warning no default label for %s\n", r_opts->progname, my_file);

		/* Check for no matching specification. */
		return (errno == ENOENT) ? 0 : -1;
	}

	if (r_opts->progress) {
		r_opts->count++;
		if (r_opts->count % STAR_COUNT == 0) {
			if (r_opts->progress == 1) {
				fprintf(stdout, "\r%luk", (size_t) r_opts->count / STAR_COUNT );
			} else {
				if (r_opts->nfile > 0) {
					progress = (r_opts->count < r_opts->nfile) ? (100.0 * r_opts->count / r_opts->nfile) : 100;
					fprintf(stdout, "\r%-.1f%%", progress);
				}
			}
			fflush(stdout);
		}
	}

	/*
	 * Try to add an association between this inode and
	 * this specification.  If there is already an association
	 * for this inode and it conflicts with this specification,
	 * then use the last matching specification.
	 */
	if (r_opts->add_assoc) {
		ret = filespec_add(ftsent->fts_statp->st_ino, newcon, my_file);
		if (ret < 0)
			goto err;

		if (ret > 0)
			/* There was already an association and it took precedence. */
			goto out;
	}

	if (r_opts->debug) {
		printf("%s:  %s matched by %s\n", r_opts->progname, my_file, newcon);
	}

	/*
	 * Do not relabel if their is no default specification for this file
	 */

	if (strcmp(newcon, "<<none>>") == 0) {
		goto out;
	}

	/* Get the current context of the file. */
	ret = lgetfilecon_raw(ftsent->fts_accpath, &curcon);
	if (ret < 0) {
		if (errno == ENODATA) {
			curcon = NULL;
		} else {
			fprintf(stderr, "%s get context on %s failed: '%s'\n",
				r_opts->progname, my_file, strerror(errno));
			goto err;
		}
	}

	/* lgetfilecon returns number of characters and ret needs to be reset
	 * to 0.
	 */
	ret = 0;

	/*
	 * Do not relabel the file if the file is already labeled according to
	 * the specification.
	 */
	if (curcon && (strcmp(curcon, newcon) == 0)) {
		goto out;
	}

	if (!r_opts->force && curcon && (is_context_customizable(curcon) > 0)) {
		if (r_opts->verbose > 1) {
			fprintf(stderr,
				"%s: %s not reset customized by admin to %s\n",
				r_opts->progname, my_file, curcon);
		}
		goto out;
	}

	/*
	 *  Do not change label unless this is a force or the type is different
	 */
	if (!r_opts->force && curcon) {
		int types_differ = 0;
		context_t cona;
		context_t conb;
		int err = 0;
		cona = context_new(curcon);
		if (! cona) {
			goto out;
		}
		conb = context_new(newcon);
		if (! conb) {
			context_free(cona);
			goto out;
		}

		types_differ = strcmp(context_type_get(cona), context_type_get(conb));
		if (types_differ) {
			err |= context_user_set(conb, context_user_get(cona));
			err |= context_role_set(conb, context_role_get(cona));
			err |= context_range_set(conb, context_range_get(cona));
			if (!err) {
				freecon(newcon);
				newcon = strdup(context_str(conb));
			}
		}
		context_free(cona);
		context_free(conb);

		if (!types_differ || err) {
			goto out;
		}
	}

	if (r_opts->verbose) {
		printf("%s reset %s context %s->%s\n",
		       r_opts->progname, my_file, curcon ?: "", newcon);
	}

	if (r_opts->logging && r_opts->change) {
		if (curcon)
			syslog(LOG_INFO, "relabeling %s from %s to %s\n",
			       my_file, curcon, newcon);
		else
			syslog(LOG_INFO, "labeling %s to %s\n",
			       my_file, newcon);
	}

	if (r_opts->outfile)
		fprintf(r_opts->outfile, "%s\n", my_file);

	/*
	 * Do not relabel the file if -n was used.
	 */
	if (!r_opts->change)
		goto out;

	/*
	 * Relabel the file to the specified context.
	 */
	ret = lsetfilecon(ftsent->fts_accpath, newcon);
	if (ret) {
		fprintf(stderr, "%s set context %s->%s failed:'%s'\n",
			r_opts->progname, my_file, newcon, strerror(errno));
		goto skip;
	}
	ret = 0;
out:
	freecon(curcon);
	freecon(newcon);
	return ret;
skip:
	freecon(curcon);
	freecon(newcon);
	return SKIP;
err:
	freecon(curcon);
	freecon(newcon);
	return ERR;
}
/*
 * Apply the last matching specification to a file.
 * This function is called by fts on each file during
 * the directory traversal.
 */
static int apply_spec(FTSENT *ftsent, int recurse)
{
	if (ftsent->fts_info == FTS_DNR) {
		fprintf(stderr, "%s:  unable to read directory %s\n",
			r_opts->progname, ftsent->fts_path);
		return SKIP;
	}
	
	int rc = restore(ftsent, recurse);
	if (rc == ERR) {
		if (!r_opts->abort_on_error)
			return SKIP;
	}
	return rc;
}

#include <sys/statvfs.h>

static int process_one(char *name, int recurse_this_path)
{
	int rc = 0;
	const char *namelist[2] = {name, NULL};
	dev_t dev_num = 0;
	FTS *fts_handle = NULL;
	FTSENT *ftsent = NULL;

	if (r_opts == NULL){
		fprintf(stderr,
			"Must call initialize first!");
		goto err;
	}

	fts_handle = fts_open((char **)namelist, r_opts->fts_flags, NULL);
	if (fts_handle  == NULL) {
		fprintf(stderr,
			"%s: error while labeling %s:  %s\n",
			r_opts->progname, namelist[0], strerror(errno));
		goto err;
	}


	ftsent = fts_read(fts_handle);
	if (ftsent == NULL) {
		fprintf(stderr,
			"%s: error while labeling %s:  %s\n",
			r_opts->progname, namelist[0], strerror(errno));
		goto err;
	}

	/* Keep the inode of the first one. */
	dev_num = ftsent->fts_statp->st_dev;

	do {
		rc = 0;
		/* Skip the post order nodes. */
		if (ftsent->fts_info == FTS_DP)
			continue;
		/* If the XDEV flag is set and the device is different */
		if (ftsent->fts_statp->st_dev != dev_num &&
		    FTS_XDEV == (r_opts->fts_flags & FTS_XDEV))
			continue;
		if (excludeCtr > 0) {
			if (exclude(ftsent->fts_path)) {
				fts_set(fts_handle, ftsent, FTS_SKIP);
				continue;
			}
		}

		rc = apply_spec(ftsent, recurse_this_path);
		if (rc == SKIP)
			fts_set(fts_handle, ftsent, FTS_SKIP);
		if (rc == ERR)
			goto err;
		if (!recurse_this_path)
			break;
	} while ((ftsent = fts_read(fts_handle)) != NULL);

out:
	if (r_opts->add_assoc) {
		if (!r_opts->quiet)
			filespec_eval();
		filespec_destroy();
	}
	if (fts_handle)
		fts_close(fts_handle);
	return rc;

err:
	rc = -1;
	goto out;
}

int process_glob(char *name, int recurse) {
	glob_t globbuf;
	size_t i = 0;
	int errors;
	memset(&globbuf, 0, sizeof(globbuf));
	errors = glob(name, GLOB_TILDE | GLOB_PERIOD | GLOB_NOCHECK | GLOB_BRACE, NULL, &globbuf);
	if (errors) 
		return errors;

	for (i = 0; i < globbuf.gl_pathc; i++) {
		int len = strlen(globbuf.gl_pathv[i]) -2;
		if (len > 0 && strcmp(&globbuf.gl_pathv[i][len--], "/.") == 0)
			continue;
		if (len > 0 && strcmp(&globbuf.gl_pathv[i][len], "/..") == 0)
			continue;
		int rc = process_one_realpath(globbuf.gl_pathv[i], recurse);
		if (rc < 0)
			errors = rc;
	}
	globfree(&globbuf);
	return errors;
}

int process_one_realpath(char *name, int recurse)
{
	int rc = 0;
	char *p;
	struct stat64 sb;

	if (r_opts == NULL){
		fprintf(stderr,
			"Must call initialize first!");
		return -1;
	}

	if (!r_opts->expand_realpath) {
		return process_one(name, recurse);
	} else {
		rc = lstat64(name, &sb);
		if (rc < 0) {
			if (r_opts->ignore_enoent && errno == ENOENT)
				return 0;
			fprintf(stderr, "%s:  lstat(%s) failed:  %s\n",
				r_opts->progname, name,	strerror(errno));
			return -1;
		}

		if (S_ISLNK(sb.st_mode)) {
			char path[PATH_MAX + 1];

			rc = realpath_not_final(name, path);
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

int exclude(const char *file)
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

int add_exclude(const char *directory)
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
		for (fl = fl_head[h].next; fl; fl = fl->next) {
			len++;
		}
		if (len)
			used++;
		if (len > longest)
			longest = len;
		nel += len;
	}

	if (r_opts->verbose > 1)
		printf
		    ("%s:  hash table stats: %d elements, %d/%d buckets used, longest chain length %d\n",
		     __FUNCTION__, nel, used, HASH_BUCKETS, longest);
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
 * Try to add an association between an inode and a context.
 * If there is a different context that matched the inode,
 * then use the first context that matched.
 */
static int filespec_add(ino_t ino, const security_context_t con, const char *file)
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

#include <sys/utsname.h>
int file_system_count(char *name) {
	struct statvfs statvfs_buf;
	int nfile = 0;
	memset(&statvfs_buf, 0, sizeof(statvfs_buf));
	if (!statvfs(name, &statvfs_buf)) {
		nfile = statvfs_buf.f_files - statvfs_buf.f_ffree;
	}
	return nfile;
}

/*
   Search /proc/mounts for all file systems that do not support extended
   attributes and add them to the exclude directory table.  File systems
   that support security labels have the seclabel option, return total file count
*/
int exclude_non_seclabel_mounts()
{
	struct utsname uts;
	FILE *fp;
	size_t len;
	ssize_t num;
	int index = 0, found = 0;
	char *mount_info[4];
	char *buf = NULL, *item;
	int nfile = 0;
	/* Check to see if the kernel supports seclabel */
	if (uname(&uts) == 0 && strverscmp(uts.release, "2.6.30") < 0)
		return 0;
	if (is_selinux_enabled() <= 0)
		return 0;

	fp = fopen("/proc/mounts", "r");
	if (!fp)
		return 0;

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
				nfile += file_system_count(mount_info[1]);
				break;
			}
			item = strtok(NULL, ",");
		}

		/* exclude mount points without the seclabel option */
		if (!found)
			add_exclude(mount_info[1]);
	}

	free(buf);
	fclose(fp);
	/* return estimated #Files + 5% for directories and hard links */
	return nfile * 1.05;
}

