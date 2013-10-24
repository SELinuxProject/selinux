/* Authors: Karl MacMillan <kmacmillan@tresys.com>
 *	    Joshua Brindle <jbrindle@tresys.com>
 *	    Jason Tang <jtang@tresys.com>
 *          Christopher Ashworth <cashworth@tresys.com>
 *          Chris PeBenito <cpebenito@tresys.com>
 *
 * Copyright (C) 2004-2006 Tresys Technology, LLC
 * Copyright (C) 2005 Red Hat, Inc.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

/* This file contains semanage routines that manipulate the files on a
 * local module store.	Sandbox routines, used by both source and
 * direct connections, are here as well.
 */

struct dbase_policydb;
typedef struct dbase_policydb dbase_t;
#define DBASE_DEFINED

#include "semanage_store.h"
#include "database_policydb.h"
#include "handle.h"

#include <selinux/selinux.h>
#include <sepol/policydb.h>
#include <sepol/module.h>

#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <limits.h>

#include "debug.h"

static const char *DISABLESTR="disabled";

#define SEMANAGE_CONF_FILE "semanage.conf"
/* relative path names to enum semanage_paths to special files and
 * directories for the module store */

#define TRUE 1

enum semanage_file_defs {
	SEMANAGE_ROOT,
	SEMANAGE_TRANS_LOCK,
	SEMANAGE_READ_LOCK,
	SEMANAGE_NUM_FILES
};

static char *semanage_paths[SEMANAGE_NUM_STORES][SEMANAGE_STORE_NUM_PATHS];
static char *semanage_files[SEMANAGE_NUM_FILES] = { NULL };
static char *semanage_conf;
static int semanage_paths_initialized = 0;

/* These are paths relative to the bottom of the module store */
static const char *semanage_relative_files[SEMANAGE_NUM_FILES] = {
	"",
	"/semanage.trans.LOCK",
	"/semanage.read.LOCK"
};

static const char *semanage_store_paths[SEMANAGE_NUM_STORES] = {
	"/active",
	"/previous",
	"/tmp"
};

/* this is the module store path relative to semanage_policy_root() */
#define SEMANAGE_MOD_DIR "/modules"
/* relative path names to enum sandbox_paths for special files within
 * a sandbox */
static const char *semanage_sandbox_paths[SEMANAGE_STORE_NUM_PATHS] = {
	"",
	"/modules",
	"/policy.kern",
	"/base.pp",
	"/base.linked",
	"/file_contexts",
	"/homedir_template",
	"/file_contexts.template",
	"/commit_num",
	"/ports.local",
	"/interfaces.local",
	"/nodes.local",
	"/booleans.local",
	"/file_contexts.local",
	"/seusers",
	"/users.local",
	"/users_extra.local",
	"/seusers.final",
	"/users_extra",
	"/netfilter_contexts",
	"/file_contexts.homedirs",
	"/disable_dontaudit",
	"/preserve_tunables",
};

/* A node used in a linked list of file contexts; used for sorting.
 */
typedef struct semanage_file_context_node {
	char *path;
	char *file_type;
	char *context;
	int path_len;
	int effective_len;
	int type_len;
	int context_len;
	int meta;		/* position of first meta char in path, -1 if none */
	struct semanage_file_context_node *next;
} semanage_file_context_node_t;

/* A node used in a linked list of buckets that contain
 *  semanage_file_context_node lists.  Used for sorting.
 */
typedef struct semanage_file_context_bucket {
	semanage_file_context_node_t *data;
	struct semanage_file_context_bucket *next;
} semanage_file_context_bucket_t;

/* A node used in a linked list of netfilter rules.
 */
typedef struct semanage_netfilter_context_node {
	char *rule;
	size_t rule_len;
	struct semanage_netfilter_context_node *next;
} semanage_netfilter_context_node_t;

/* Initialize the paths to config file, lock files and store root.
 */
static int semanage_init_paths(const char *root)
{
	size_t len, prefix_len;
	int i;

	if (!root)
		return -1;

	prefix_len = (strlen(root) + strlen(SEMANAGE_MOD_DIR));

	for (i = 0; i < SEMANAGE_NUM_FILES; i++) {
		len = (strlen(semanage_relative_files[i]) + prefix_len);
		semanage_files[i] = calloc(len + 1, sizeof(char));
		if (!semanage_files[i])
			return -1;
		sprintf(semanage_files[i], "%s%s%s", root, SEMANAGE_MOD_DIR,
			semanage_relative_files[i]);
	}

	len = strlen(semanage_selinux_path()) + strlen(SEMANAGE_CONF_FILE);
	semanage_conf = calloc(len + 1, sizeof(char));
	if (!semanage_conf)
		return -1;
	snprintf(semanage_conf, len, "%s%s", semanage_selinux_path(),
		 SEMANAGE_CONF_FILE);

	return 0;
}

/* This initializes the paths inside the stores, this is only necessary 
 * when directly accessing the store
 */
static int semanage_init_store_paths(const char *root)
{
	int i, j;
	size_t len;
	size_t prefix_len;
	char *prefix;

	if (!root)
		return -1;

	prefix_len = (strlen(root) + strlen(SEMANAGE_MOD_DIR));
	prefix = calloc(prefix_len + 1, sizeof(char));
	if (!prefix)
		return -1;
	sprintf(prefix, "%s%s", root, SEMANAGE_MOD_DIR);

	for (i = 0; i < SEMANAGE_NUM_STORES; i++) {
		for (j = 0; j < SEMANAGE_STORE_NUM_PATHS; j++) {
			len = prefix_len + strlen(semanage_store_paths[i])
			    + strlen(semanage_sandbox_paths[j]);
			semanage_paths[i][j] = calloc(len + 1, sizeof(char));
			if (!semanage_paths[i][j])
				goto cleanup;
			sprintf(semanage_paths[i][j], "%s%s%s", prefix,
				semanage_store_paths[i],
				semanage_sandbox_paths[j]);
		}
	}

      cleanup:
	free(prefix);
	return 0;
}

/* THIS MUST BE THE FIRST FUNCTION CALLED IN THIS LIBRARY.  If the
 * library has nnot been initialized yet then call the functions that
 * initialize the path variables.  This function does nothing if it
 * was previously called and that call was successful.  Return 0 on
 * success, -1 on error.
 *
 * Note that this function is NOT thread-safe.
 */
int semanage_check_init(const char *root)
{
	int rc;
	if (semanage_paths_initialized == 0) {
		rc = semanage_init_paths(root);
		if (rc)
			return rc;
		rc = semanage_init_store_paths(root);
		if (rc)
			return rc;
		semanage_paths_initialized = 1;
	}
	return 0;
}

/* Given a definition number, return a file name from the paths array */
const char *semanage_fname(enum semanage_sandbox_defs file_enum)
{
	return semanage_sandbox_paths[file_enum];
}

/* Given a store location (active/previous/tmp) and a definition
 * number, return a fully-qualified path to that file or directory.
 * The caller must not alter the string returned (and hence why this
 * function return type is const).
 *
 * This function shall never return a NULL, assuming that
 * semanage_check_init() was previously called.
 */
const char *semanage_path(enum semanage_store_defs store,
			  enum semanage_sandbox_defs path_name)
{
	assert(semanage_paths[store][path_name]);
	return semanage_paths[store][path_name];
}

/**************** functions that create module store ***************/

/* Check that the semanage store exists.  If 'create' is non-zero then
 * create the directories.  Returns 0 if module store exists (either
 * already or just created), -1 if does not exist or could not be
 * read, or -2 if it could not create the store. */
int semanage_create_store(semanage_handle_t * sh, int create)
{
	struct stat sb;
	int mode_mask = R_OK | W_OK | X_OK;
	const char *path = semanage_files[SEMANAGE_ROOT];
	int fd;

	if (stat(path, &sb) == -1) {
		if (errno == ENOENT && create) {
			if (mkdir(path, S_IRWXU) == -1) {
				ERR(sh, "Could not create module store at %s.",
				    path);
				return -2;
			}
		} else {
			if (create)
				ERR(sh,
				    "Could not read from module store at %s.",
				    path);
			return -1;
		}
	} else {
		if (!S_ISDIR(sb.st_mode) || access(path, mode_mask) == -1) {
			ERR(sh,
			    "Could not access module store at %s, or it is not a directory.",
			    path);
			return -1;
		}
	}
	path = semanage_path(SEMANAGE_ACTIVE, SEMANAGE_TOPLEVEL);
	if (stat(path, &sb) == -1) {
		if (errno == ENOENT && create) {
			if (mkdir(path, S_IRWXU) == -1) {
				ERR(sh,
				    "Could not create module store, active subdirectory at %s.",
				    path);
				return -2;
			}
		} else {
			ERR(sh,
			    "Could not read from module store, active subdirectory at %s.",
			    path);
			return -1;
		}
	} else {
		if (!S_ISDIR(sb.st_mode) || access(path, mode_mask) == -1) {
			ERR(sh,
			    "Could not access module store active subdirectory at %s, or it is not a directory.",
			    path);
			return -1;
		}
	}
	path = semanage_path(SEMANAGE_ACTIVE, SEMANAGE_MODULES);
	if (stat(path, &sb) == -1) {
		if (errno == ENOENT && create) {
			if (mkdir(path, S_IRWXU) == -1) {
				ERR(sh,
				    "Could not create module store, active modules subdirectory at %s.",
				    path);
				return -2;
			}
		} else {
			ERR(sh,
			    "Could not read from module store, active modules subdirectory at %s.",
			    path);
			return -1;
		}
	} else {
		if (!S_ISDIR(sb.st_mode) || access(path, mode_mask) == -1) {
			ERR(sh,
			    "Could not access module store active modules subdirectory at %s, or it is not a directory.",
			    path);
			return -1;
		}
	}
	path = semanage_files[SEMANAGE_READ_LOCK];
	if (stat(path, &sb) == -1) {
		if (errno == ENOENT && create) {
			if ((fd = creat(path, S_IRUSR | S_IWUSR)) == -1) {
				ERR(sh, "Could not create lock file at %s.",
				    path);
				return -2;
			}
			close(fd);
		} else {
			ERR(sh, "Could not read lock file at %s.", path);
			return -1;
		}
	} else {
		if (!S_ISREG(sb.st_mode) || access(path, R_OK | W_OK) == -1) {
			ERR(sh, "Could not access lock file at %s.", path);
			return -1;
		}
	}
	return 0;
}

/* returns <0 if the active store cannot be read or doesn't exist
 * 0 if the store exists but the lock file cannot be accessed 
 * SEMANAGE_CAN_READ if the store can be read and the lock file used
 * SEMANAGE_CAN_WRITE if the modules directory and binary policy dir can be written to
 */
int semanage_store_access_check(void)
{
	const char *path;
	int rc = -1;

	/* read access on active store */
	path = semanage_path(SEMANAGE_ACTIVE, SEMANAGE_TOPLEVEL);
	if (access(path, R_OK | X_OK) != 0)
		goto out;

	/* we can read the active store meaning it is managed
	 * so now we return 0 to indicate no error */
	rc = 0;

	/* read access on lock file required for locking
	 * write access necessary if the lock file does not exist
	 */
	path = semanage_files[SEMANAGE_READ_LOCK];
	if (access(path, R_OK) != 0) {
		if (access(path, F_OK) == 0) {
			goto out;
		}

		path = semanage_files[SEMANAGE_ROOT];
		if (access(path, R_OK | W_OK | X_OK) != 0) {
			goto out;
		}
	}

	/* everything needed for reading has been checked */
	rc = SEMANAGE_CAN_READ;

	/* check the modules directory */
	path = semanage_path(SEMANAGE_ACTIVE, SEMANAGE_MODULES);
	if (access(path, R_OK | W_OK | X_OK) != 0)
		goto out;

	rc = SEMANAGE_CAN_WRITE;

      out:
	return rc;
}

/********************* other I/O functions *********************/

static int is_disabled_file(const char *file) {
	char *ptr = strrchr(file, '.');
	if (! ptr) return 0;
	ptr++;
	return (strcmp(ptr, DISABLESTR) == 0);
}

/* Callback used by scandir() to select files. */
static int semanage_filename_select(const struct dirent *d)
{
	if (d->d_name[0] == '.'
	    && (d->d_name[1] == '\0'
		|| (d->d_name[1] == '.' && d->d_name[2] == '\0')))
		return 0;
	return 1;
}

int semanage_disable_module(const char *file) {
	char path[PATH_MAX];
	int in;
	int n = snprintf(path, PATH_MAX, "%s.%s", file, DISABLESTR);
	if (n < 0 || n >= PATH_MAX)
		return -1;
	if ((in = open(path, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR)) == -1) {
		return -1;
	}
	close(in);
	return 0;
}

int semanage_enable_module(const char *file) {
	char path[PATH_MAX];
	int n = snprintf(path, PATH_MAX, "%s.%s", file, DISABLESTR);
	if (n < 0 || n >= PATH_MAX)
		return -1;

	if ((unlink(path) < 0) && (errno != ENOENT))
		return -1;
	return 0;
}

int semanage_module_enabled(const char *file) {
	char path[PATH_MAX];
	if (is_disabled_file(file)) return 0;
	int n = snprintf(path, PATH_MAX, "%s.%s", file, DISABLESTR);
	if (n < 0 || n >= PATH_MAX)
		return 1;

	return (access(path, F_OK ) != 0);
}

/* Callback used by scandir() to select module files. */
static int semanage_modulename_select(const struct dirent *d)
{
	if (d->d_name[0] == '.'
	    && (d->d_name[1] == '\0'
		|| (d->d_name[1] == '.' && d->d_name[2] == '\0')))
		return 0;

	return (! is_disabled_file(d->d_name));
}

/* Copies a file from src to dst.  If dst already exists then
 * overwrite it.  Returns 0 on success, -1 on error. */
static int semanage_copy_file(const char *src, const char *dst, mode_t mode)
{
	int in, out, retval = 0, amount_read, n, errsv = errno;
	char tmp[PATH_MAX];
	char buf[4192];
	mode_t mask;

	n = snprintf(tmp, PATH_MAX, "%s.tmp", dst);
	if (n < 0 || n >= PATH_MAX)
		return -1;

	if ((in = open(src, O_RDONLY)) == -1) {
		return -1;
	}

	if (!mode)
		mode = S_IRUSR | S_IWUSR;
	
	mask = umask(0);
	if ((out = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, mode)) == -1) {
		umask(mask);
		errsv = errno;
		close(in);
		retval = -1;
		goto out;
	}
	umask(mask);
	while (retval == 0 && (amount_read = read(in, buf, sizeof(buf))) > 0) {
		if (write(out, buf, amount_read) < 0) {
			errsv = errno;
			retval = -1;
		}
	}
	if (amount_read < 0) {
		errsv = errno;
		retval = -1;
	}
	close(in);
	if (close(out) < 0) {
		errsv = errno;
		retval = -1;
	}

	if (!retval && rename(tmp, dst) == -1)
		return -1;

out:
	errno = errsv;
	return retval;
}

/* Copies all of the files from src to dst, recursing into
 * subdirectories.  Returns 0 on success, -1 on error. */
static int semanage_copy_dir(const char *src, const char *dst)
{
	int i, len = 0, retval = -1;
	struct stat sb;
	struct dirent **names = NULL;
	char path[PATH_MAX], path2[PATH_MAX];

	if ((len = scandir(src, &names, semanage_filename_select, NULL)) == -1) {
		return -1;
	}
	for (i = 0; i < len; i++) {
		snprintf(path, sizeof(path), "%s/%s", src, names[i]->d_name);
		/* stat() to see if this entry is a file or not since
		 * d_type isn't set properly on XFS */
		if (stat(path, &sb)) {
			goto cleanup;
		}
		snprintf(path2, sizeof(path2), "%s/%s", dst, names[i]->d_name);
		if (S_ISDIR(sb.st_mode)) {
			if (mkdir(path2, 0700) == -1 ||
			    semanage_copy_dir(path, path2) == -1) {
				goto cleanup;
			}
		} else if (S_ISREG(sb.st_mode)) {
			if (semanage_copy_file(path, path2, sb.st_mode) == -1) {
				goto cleanup;
			}
		}
	}
	retval = 0;
      cleanup:
	for (i = 0; names != NULL && i < len; i++) {
		free(names[i]);
	}
	free(names);
	return retval;
}

/* Recursively removes the contents of a directory along with the
 * directory itself.  Returns 0 on success, non-zero on error. */
int semanage_remove_directory(const char *path)
{
	struct dirent **namelist = NULL;
	int num_entries, i;
	if ((num_entries = scandir(path, &namelist, semanage_filename_select,
				   NULL)) == -1) {
		return -1;
	}
	for (i = 0; i < num_entries; i++) {
		char s[NAME_MAX];
		struct stat buf;
		snprintf(s, sizeof(s), "%s/%s", path, namelist[i]->d_name);
		if (stat(s, &buf) == -1) {
			return -2;
		}
		if (S_ISDIR(buf.st_mode)) {
			int retval;
			if ((retval = semanage_remove_directory(s)) != 0) {
				return retval;
			}
		} else {
			if (remove(s) == -1) {
				return -3;
			}
		}
		free(namelist[i]);
	}
	free(namelist);
	if (rmdir(path) == -1) {
		return -4;
	}
	return 0;
}

/********************* sandbox management routines *********************/

/* Creates a sandbox for a single client. Returns 0 if a
 * sandbox was created, -1 on error.
 */
int semanage_make_sandbox(semanage_handle_t * sh)
{
	const char *sandbox = semanage_path(SEMANAGE_TMP, SEMANAGE_TOPLEVEL);
	struct stat buf;
	int errsv;

	if (stat(sandbox, &buf) == -1) {
		if (errno != ENOENT) {
			ERR(sh, "Error scanning directory %s.", sandbox);
			return -1;
		}
		errno = 0;
	} else {
		/* remove the old sandbox */
		if (semanage_remove_directory(sandbox) != 0) {
			ERR(sh, "Error removing old sandbox directory %s.",
			    sandbox);
			return -1;
		}
	}

	if (mkdir(sandbox, S_IRWXU) == -1 ||
	    semanage_copy_dir(semanage_path(SEMANAGE_ACTIVE, SEMANAGE_TOPLEVEL),
			      sandbox) == -1) {
		ERR(sh, "Could not copy files to sandbox %s.", sandbox);
		goto cleanup;
	}
	return 0;

      cleanup:
	errsv = errno;
	semanage_remove_directory(sandbox);
	errno = errsv;
	return -1;
}

static int semanage_get_modules_names_filter(semanage_handle_t * sh, char ***filenames,
				      int *len, int (*filter)(const struct dirent *))
{
	const char *modules_path;
	struct dirent **namelist = NULL;
	int num_files, i, retval = -1;

	if (sh->is_in_transaction) {
		modules_path = semanage_path(SEMANAGE_TMP, SEMANAGE_MODULES);
	} else {
		modules_path = semanage_path(SEMANAGE_ACTIVE, SEMANAGE_MODULES);
	}

	*filenames = NULL;
	*len = 0;
	if ((num_files = scandir(modules_path, &namelist,
				 filter, alphasort)) == -1) {
		ERR(sh, "Error while scanning directory %s.", modules_path);
		goto cleanup;
	}
	if (num_files == 0) {
		retval = 0;
		goto cleanup;
	}
	if ((*filenames =
	     (char **)calloc(num_files, sizeof(**filenames))) == NULL) {
		ERR(sh, "Out of memory!");
		goto cleanup;
	}
	for (i = 0; i < num_files; i++) {
		char *filename;
		char path[PATH_MAX];

		snprintf(path, PATH_MAX, "%s/%s", modules_path,
			 namelist[i]->d_name);
		if ((filename = strdup(path)) == NULL) {
			int j;
			ERR(sh, "Out of memory!");
			for (j = 0; j < i; j++) {
				free((*filenames)[j]);
			}
			free(*filenames);
			*filenames = NULL;
			goto cleanup;
		}
		(*filenames)[i] = filename;
	}
	*len = num_files;
	retval = 0;
      cleanup:
	for (i = 0; i < num_files; i++) {
		free(namelist[i]);
	}
	free(namelist);
	return retval;
}

/* Scans the modules directory for the current semanage handler.  This
 * might be the active directory or sandbox, depending upon if the
 * handler has a transaction lock.  Allocates and fills in *filenames
 * with an array of module filenames; length of array is stored in
 * *len.  The caller is responsible for free()ing *filenames and its
 * individual elements.	 Upon success returns 0, -1 on error.
 */
int semanage_get_modules_names(semanage_handle_t * sh, char ***filenames,
			       int *len)
{
	return semanage_get_modules_names_filter(sh, filenames,
						 len, semanage_modulename_select);
}

/* Scans the modules directory for the current semanage handler.  This
 * might be the active directory or sandbox, depending upon if the
 * handler has a transaction lock.  Allocates and fills in *filenames
 * with an array of module filenames; length of array is stored in
 * *len.  The caller is responsible for free()ing *filenames and its
 * individual elements.	 Upon success returns 0, -1 on error.
 */
int semanage_get_active_modules_names(semanage_handle_t * sh, char ***filenames,
			       int *len)
{

	int rc = semanage_get_modules_names_filter(sh, filenames,
						   len, semanage_modulename_select);
	if ( rc != 0 ) return rc;

	int i = 0, num_modules = *len;
	char **names=*filenames;

	while ( i < num_modules ) {
		if (! semanage_module_enabled(names[i])) {
			free(names[i]);
			names[i]=names[num_modules-1];
			names[num_modules-1] = NULL;
			num_modules--;
		}
		i++;
	}
	*len = num_modules;
	return 0;
}

/******************* routines that run external programs *******************/

/* Appends a single character to a string.  Returns a pointer to the
 * realloc()ated string.  If out of memory return NULL; original
 * string will remain untouched.
 */
static char *append(char *s, char c)
{
	size_t len = (s == NULL ? 0 : strlen(s));
	char *new_s = realloc(s, len + 2);
	if (new_s == NULL) {
		return NULL;
	}
	s = new_s;
	s[len] = c;
	s[len + 1] = '\0';
	return s;
}

/* Append string 't' to string 's', realloc()ating 's' as needed.  't'
 * may be safely free()d afterwards.  Returns a pointer to the
 * realloc()ated 's'.  If out of memory return NULL; original strings
 * will remain untouched.
 */
static char *append_str(char *s, const char *t)
{
	size_t s_len = (s == NULL ? 0 : strlen(s));
	size_t t_len = (t == NULL ? 0 : strlen(t));
	char *new_s = realloc(s, s_len + t_len + 1);
	if (new_s == NULL) {
		return NULL;
	}
	s = new_s;
	memcpy(s + s_len, t, t_len);
	s[s_len + t_len] = '\0';
	return s;
}

/*
 * Append an argument string to an argument vector.  Replaces the
 * argument pointer passed in.  Returns -1 on error.  Increments
 * 'num_args' on success.
 */
static int append_arg(char ***argv, int *num_args, const char *arg)
{
	char **a;

	a = realloc(*argv, sizeof(**argv) * (*num_args + 1));
	if (a == NULL)
		return -1;

	*argv = a;
	a[*num_args] = NULL;

	if (arg) {
		a[*num_args] = strdup(arg);
		if (!a[*num_args])
			return -1;
	}
	(*num_args)++;
	return 0;
}

/* free()s all strings within a null-terminated argument vector, as
 * well as the pointer itself. */
static void free_argv(char **argv)
{
	int i;
	for (i = 0; argv != NULL && argv[i] != NULL; i++) {
		free(argv[i]);
	}
	free(argv);
}

/* Take an argument string and split and place into an argument
 * vector.  Respect normal quoting, double-quoting, and backslash
 * conventions.	 Perform substitutions on $@ and $< symbols.  Returns
 * a NULL-terminated argument vector; caller is responsible for
 * free()ing the vector and its elements. */
static char **split_args(const char *arg0, char *arg_string,
			 const char *new_name, const char *old_name)
{
	char **argv = NULL, *s, *arg = NULL, *targ;
	int num_args = 0, in_quote = 0, in_dquote = 0, rc;

	rc = append_arg(&argv, &num_args, arg0);
	if (rc)
		goto cleanup;
	s = arg_string;
	/* parse the argument string one character at a time,
	 * repsecting quotes and other special characters */
	while (s != NULL && *s != '\0') {
		switch (*s) {
		case '\\':{
				if (*(s + 1) == '\0') {
					targ = append(arg, '\\');
					if (targ == NULL)
						goto cleanup;
					arg = targ;
				} else {
					targ = append(arg, *(s + 1));
					if (targ == NULL)
						goto cleanup;
					arg = targ;
					s++;
				}
				break;
			}
		case '\'':{
				if (in_dquote) {
					targ = append(arg, *s);
					if (targ == NULL)
						goto cleanup;
					arg = targ;
				} else if (in_quote) {
					in_quote = 0;
				} else {
					in_quote = 1;
					targ = append(arg, '\0');
					if (targ == NULL)
						goto cleanup;
					arg = targ;
				}
				break;
			}
		case '\"':{
				if (in_quote) {
					targ = append(arg, *s);
					if (targ == NULL)
						goto cleanup;
					arg = targ;
				} else if (in_dquote) {
					in_dquote = 0;
				} else {
					in_dquote = 1;
					targ = append(arg, '\0');
					if (targ == NULL)
						goto cleanup;
					arg = targ;
				}
				break;
			}
		case '$':{
				switch (*(s + 1)) {
				case '@':{
						targ = append_str(arg, new_name);
						if (targ == NULL)
							goto cleanup;
						arg = targ;
						s++;
						break;
					}
				case '<':{
						targ = append_str(arg, old_name);
						if (targ == NULL)
							goto cleanup;
						arg = targ;
						s++;
						break;
					}
				default:{
						targ = append(arg, *s);
						if (targ == NULL)
							goto cleanup;
						arg = targ;
					}
				}
				break;
			}
		default:{
				if (isspace(*s) && !in_quote && !in_dquote) {
					if (arg != NULL) {
						rc = append_arg(&argv, &num_args, arg);
						free(arg);
						arg = NULL;
					}
				} else {
					if ((targ = append(arg, *s)) == NULL) {
						goto cleanup;
					} else {
						arg = targ;
					}
				}
			}
		}
		s++;
	}
	if (arg != NULL) {
		rc = append_arg(&argv, &num_args, arg);
		free(arg);
		arg = NULL;
	}
	/* explicitly add a NULL at the end */
	rc = append_arg(&argv, &num_args, NULL);
	if (rc)
		goto cleanup;
	return argv;
      cleanup:
	free_argv(argv);
	free(arg);
	return NULL;
}

/* Take the arguments given in v->args and expand any $ macros within.
 * Split the arguments into different strings (argv).  Next fork and
 * execute the process.	 BE SURE THAT ALL FILE DESCRIPTORS ARE SET TO
 * CLOSE-ON-EXEC.  Take the return value of the child process and
 * return it, -1 on error.
 */
static int semanage_exec_prog(semanage_handle_t * sh,
			      external_prog_t * e, const char *new_name,
			      const char *old_name)
{
	char **argv;
	pid_t forkval;
	int status = 0;

	argv = split_args(e->path, e->args, new_name, old_name);
	if (argv == NULL) {
		ERR(sh, "Out of memory!");
		return -1;
	}

	/* no need to use pthread_atfork() -- child will not be using
	 * any mutexes. */
	forkval = vfork();
	if (forkval == 0) {
		/* child process.  file descriptors will be closed
		 * because they were set as close-on-exec. */
		execve(e->path, argv, NULL);
		_exit(EXIT_FAILURE);	/* if execve() failed */
	}

	free_argv(argv);

	if (forkval == -1) {
		ERR(sh, "Error while forking process.");
		return -1;
	}

	/* parent process.  wait for child to finish */
	if (waitpid(forkval, &status, 0) == -1 || !WIFEXITED(status)) {
		ERR(sh, "Child process %s did not exit cleanly.",
		    e->path);
		return -1;
	}
	return WEXITSTATUS(status);
}

/* reloads the policy pointed to by the handle, used locally by install 
 * and exported for user reload requests */
int semanage_reload_policy(semanage_handle_t * sh)
{
	int r = 0;

	if (!sh)
		return -1;

	if ((r = semanage_exec_prog(sh, sh->conf->load_policy, "", "")) != 0) {
		ERR(sh, "load_policy returned error code %d.", r);
	}
	return r;
}

hidden_def(semanage_reload_policy)

/* This expands the file_context.tmpl file to file_context and homedirs.template */
int semanage_split_fc(semanage_handle_t * sh)
{
	FILE *file_con = NULL;
	int fc = -1, hd = -1, retval = -1;
	char buf[PATH_MAX] = { 0 };

	/* I use fopen here instead of open so that I can use fgets which only reads a single line */
	file_con = fopen(semanage_path(SEMANAGE_TMP, SEMANAGE_FC_TMPL), "r");
	if (!file_con) {
		ERR(sh, "Could not open %s for reading.",
		    semanage_path(SEMANAGE_TMP, SEMANAGE_FC_TMPL));
		goto cleanup;
	}

	fc = open(semanage_path(SEMANAGE_TMP, SEMANAGE_FC),
		  O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (!fc) {
		ERR(sh, "Could not open %s for writing.",
		    semanage_path(SEMANAGE_TMP, SEMANAGE_FC));
		goto cleanup;
	}
	hd = open(semanage_path(SEMANAGE_TMP, SEMANAGE_HOMEDIR_TMPL),
		  O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (hd < 0) {
		ERR(sh, "Could not open %s for writing.",
		    semanage_path(SEMANAGE_TMP, SEMANAGE_HOMEDIR_TMPL));
		goto cleanup;
	}

	while (fgets_unlocked(buf, PATH_MAX, file_con)) {
		if (!strncmp(buf, "HOME_DIR", 8) ||
		    !strncmp(buf, "HOME_ROOT", 9) || strstr(buf, "ROLE") ||
		    strstr(buf, "USER")) {
			/* This contains one of the template variables, write it to homedir.template */
			if (write(hd, buf, strlen(buf)) < 0) {
				ERR(sh, "Write to %s failed.",
				    semanage_path(SEMANAGE_TMP,
						  SEMANAGE_HOMEDIR_TMPL));
				goto cleanup;
			}
		} else {
			if (write(fc, buf, strlen(buf)) < 0) {
				ERR(sh, "Write to %s failed.",
				    semanage_path(SEMANAGE_TMP, SEMANAGE_FC));
				goto cleanup;
			}
		}
	}

	retval = 0;
      cleanup:
	if (file_con)
		fclose(file_con);
	if (fc >= 0)
		close(fc);
	if (hd >= 0)
		close(hd);

	return retval;

}

static int sefcontext_compile(semanage_handle_t * sh, const char *path) {

	int r;
	if ((r = semanage_exec_prog(sh, sh->conf->sefcontext_compile, path, "")) != 0) {
		ERR(sh, "sefcontext_compile returned error code %d. Compiling %s", r, path);
		return -1;
	}

	return 0;
}

/* Actually load the contents of the current active directory into the
 * kernel.  Return 0 on success, -3 on error. */
static int semanage_install_active(semanage_handle_t * sh)
{
	int retval = -3, r, len;
	char *storepath = NULL;
	struct stat astore, istore;
	const char *active_kernel = semanage_path(SEMANAGE_ACTIVE, SEMANAGE_KERNEL);
	const char *active_fc = semanage_path(SEMANAGE_ACTIVE, SEMANAGE_FC);
	const char *active_fc_loc = semanage_path(SEMANAGE_ACTIVE, SEMANAGE_FC_LOCAL);
	const char *active_seusers = semanage_path(SEMANAGE_ACTIVE, SEMANAGE_SEUSERS);
	const char *active_nc = semanage_path(SEMANAGE_ACTIVE, SEMANAGE_NC);
	const char *active_fc_hd = semanage_path(SEMANAGE_ACTIVE, SEMANAGE_FC_HOMEDIRS);

	const char *running_fc = semanage_file_context_path();
	const char *running_fc_loc = semanage_file_context_local_path();
	const char *running_fc_hd = semanage_file_context_homedir_path();
	const char *running_hd = semanage_homedir_context_path();
	const char *running_policy = semanage_binary_policy_path();
	const char *running_seusers = semanage_usersconf_path();
	const char *running_nc = semanage_netfilter_context_path();
	const char *really_active_store = semanage_policy_root();

	/* This is very unelegant, the right thing to do is export the path 
	 * building code in libselinux so that you can get paths for a given 
	 * POLICYTYPE and should probably be done in the future. */
	char store_fc[PATH_MAX];
	char store_fc_loc[PATH_MAX];
	char store_pol[PATH_MAX];
	char store_seusers[PATH_MAX];
	char store_nc[PATH_MAX];
	char store_fc_hd[PATH_MAX];

	len = strlen(really_active_store);
	running_fc += len;
	running_fc_loc += len;
	running_fc_hd += len;
	running_hd += len;
	running_policy += len;
	running_seusers += len;
	running_nc += len;

	if (asprintf(&storepath, "%s%s", semanage_selinux_path(), sh->conf->store_path) < 0)
		return retval;

	snprintf(store_pol, PATH_MAX, "%s%s.%d", storepath,
		 running_policy, sh->conf->policyvers);
	if (semanage_copy_file(active_kernel, store_pol, sh->conf->file_mode) ==
	    -1) {
		ERR(sh, "Could not copy %s to %s.", active_kernel, store_pol);
		goto cleanup;
	}

	if (!sh->conf->disable_genhomedircon) {
		snprintf(store_fc_hd, PATH_MAX, "%s%s", storepath, running_fc_hd);
		if (semanage_copy_file(active_fc_hd, store_fc_hd, sh->conf->file_mode)
			== -1) {
			ERR(sh, "Could not copy %s to %s.", active_fc_hd, store_fc_hd);
			goto cleanup;
		}
	}

	snprintf(store_fc, PATH_MAX, "%s%s", storepath, running_fc);
	if (semanage_copy_file(active_fc, store_fc, sh->conf->file_mode) == -1) {
		ERR(sh, "Could not copy %s to %s.", active_fc, store_fc);
		goto cleanup;
	}

	snprintf(store_fc_loc, PATH_MAX, "%s%s", storepath, running_fc_loc);
	if (semanage_copy_file(active_fc_loc, store_fc_loc, sh->conf->file_mode)
	    == -1 && errno != ENOENT) {
		ERR(sh, "Could not copy %s to %s.", active_fc_loc,
		    store_fc_loc);
		goto cleanup;
	}
	errno = 0;

	snprintf(store_seusers, PATH_MAX, "%s%s", storepath, running_seusers);
	if (semanage_copy_file
	    (active_seusers, store_seusers, sh->conf->file_mode) == -1
	    && errno != ENOENT) {
		ERR(sh, "Could not copy %s to %s.", active_seusers,
		    store_seusers);
		goto cleanup;
	}
	errno = 0;

	snprintf(store_nc, PATH_MAX, "%s%s", storepath, running_nc);
	if (semanage_copy_file(active_nc, store_nc, sh->conf->file_mode) == -1
	    && errno != ENOENT) {
		ERR(sh, "Could not copy %s to %s.", active_nc, store_nc);
		goto cleanup;
	}
	errno = 0;

	if (!sh->do_reload)
		goto skip_reload;

	/* This stats what libselinux says the active store is (according to config)
	 * and what we are installing to, to decide if they are the same store. If
	 * they are not then we do not reload policy */

	if (stat(really_active_store, &astore) == 0) {

		if (stat(storepath, &istore)) {
			ERR(sh, "Could not stat store path %s.", storepath);
			goto cleanup;
		}

		if (!(astore.st_ino == istore.st_ino &&
		      astore.st_dev == istore.st_dev)) {
			/* They are not the same store */
			goto skip_reload;
		}
	} else if (errno == ENOENT &&
		   strcmp(really_active_store, storepath) != 0) {
		errno = 0;
		goto skip_reload;
	}

	if (semanage_reload_policy(sh)) {
		goto cleanup;
	}

      skip_reload:

	if (sh->do_check_contexts && (r =
	     semanage_exec_prog(sh, sh->conf->setfiles, store_pol,
				store_fc)) != 0) {
		ERR(sh, "setfiles returned error code %d.", r);
		goto cleanup;
	}

	if (sefcontext_compile(sh, store_fc) != 0) {
		goto cleanup;
	}
	if (sefcontext_compile(sh, store_fc_loc) != 0) {
		goto cleanup;
	}
	if (sefcontext_compile(sh, store_fc_hd) != 0) {
		goto cleanup;
	}

	retval = 0;
      cleanup:
	(void) unlink(active_kernel);
	if (symlink(store_pol, active_kernel) < 0) {
		ERR(sh, "Unable to create sybolic link from %s to %s error code %d.", active_kernel, store_pol, r);
	}
	free(storepath);
	return retval;
}

/* Prepare the sandbox to be installed by making a backup of the
 * current active directory.  Then copy the sandbox to the active
 * directory.  Return the new commit number on success, negative
 * values on error. */
static int semanage_commit_sandbox(semanage_handle_t * sh)
{
	int commit_number, fd, retval;
	char write_buf[32];
	const char *commit_filename =
	    semanage_path(SEMANAGE_TMP, SEMANAGE_COMMIT_NUM_FILE);
	ssize_t amount_written;
	const char *active = semanage_path(SEMANAGE_ACTIVE, SEMANAGE_TOPLEVEL);
	const char *backup =
	    semanage_path(SEMANAGE_PREVIOUS, SEMANAGE_TOPLEVEL);
	const char *sandbox = semanage_path(SEMANAGE_TMP, SEMANAGE_TOPLEVEL);
	struct stat buf;

	/* update the commit number */
	if ((commit_number = semanage_direct_get_serial(sh)) < 0) {
		return -1;
	}
	commit_number++;
	memset(write_buf, 0, sizeof(write_buf));
	snprintf(write_buf, sizeof(write_buf), "%d", commit_number);
	if ((fd =
	     open(commit_filename, O_WRONLY | O_CREAT | O_TRUNC,
		  S_IRUSR | S_IWUSR)) == -1) {
		ERR(sh, "Could not open commit number file %s for writing.",
		    commit_filename);
		return -1;
	}
	amount_written = write(fd, write_buf, sizeof(write_buf));
	if (amount_written == -1) {
		ERR(sh, "Error while writing commit number to %s.",
		    commit_filename);
		close(fd);
		return -1;
	}
	close(fd);

	retval = commit_number;

	if (semanage_get_active_lock(sh) < 0) {
		return -1;
	}
	/* make the backup of the current active directory */
	if (stat(backup, &buf) == 0) {
		if (S_ISDIR(buf.st_mode) &&
		    semanage_remove_directory(backup) != 0) {
			ERR(sh, "Could not remove previous backup %s.", backup);
			retval = -1;
			goto cleanup;
		}
	} else if (errno != ENOENT) {
		ERR(sh, "Could not stat directory %s.", backup);
		retval = -1;
		goto cleanup;
	}

	if (rename(active, backup) == -1) {
		ERR(sh, "Error while renaming %s to %s.", active, backup);
		retval = -1;
		goto cleanup;
	}

	/* clean up some files from the sandbox before install */
	/* remove homedir_template from sandbox */

	if (rename(sandbox, active) == -1) {
		ERR(sh, "Error while renaming %s to %s.", sandbox, active);
		/* note that if an error occurs during the next
		 * function then the store will be left in an
		 * inconsistent state */
		if (rename(backup, active) < 0)
			ERR(sh, "Error while renaming %s back to %s.", backup,
			    active);
		retval = -1;
		goto cleanup;
	}
	if (semanage_install_active(sh) != 0) {
		/* note that if an error occurs during the next three
		 * function then the store will be left in an
		 * inconsistent state */
		int errsv = errno;
		if (rename(active, sandbox) < 0)
			ERR(sh, "Error while renaming %s back to %s.", active,
			    sandbox);
		else if (rename(backup, active) < 0)
			ERR(sh, "Error while renaming %s back to %s.", backup,
			    active);
		else
			semanage_install_active(sh);
		errno = errsv;
		retval = -1;
		goto cleanup;
	}

	if (!sh->conf->save_previous) {
		int errsv = errno;
		retval = semanage_remove_directory(backup);
		if (retval < 0) {
			ERR(sh, "Could not delete previous directory %s.", backup);
			goto cleanup;
		}
		errno = errsv;
	}

      cleanup:
	semanage_release_active_lock(sh);
	return retval;
}

/* Takes the kernel policy in a sandbox, move it to the active
 * directory, copy it to the binary policy path, then load it.	Upon
 * error move the active directory back to the sandbox.	 This function
 * should be placed within a mutex lock to ensure that it runs
 * atomically.	Returns commit number on success, -1 on error.
 */
int semanage_install_sandbox(semanage_handle_t * sh)
{
	int retval = -1, commit_num = -1;

	if (sh->conf->load_policy == NULL) {
		ERR(sh,
		    "No load_policy program specified in configuration file.");
		goto cleanup;
	}
	if (sh->conf->setfiles == NULL) {
		ERR(sh, "No setfiles program specified in configuration file.");
		goto cleanup;
	}

	if (sh->conf->sefcontext_compile == NULL) {
		ERR(sh, "No sefcontext_compile program specified in configuration file.");
		goto cleanup;
	}

	if ((commit_num = semanage_commit_sandbox(sh)) < 0) {
		retval = commit_num;
		goto cleanup;
	}

	retval = commit_num;

      cleanup:
	return retval;

}

/********************* functions that manipulate lock *********************/

static int semanage_get_lock(semanage_handle_t * sh,
			     const char *lock_name, const char *lock_file)
{
	int fd;
	struct timeval origtime, curtime;
	int got_lock = 0;

	if ((fd = open(lock_file, O_RDONLY)) == -1) {
		if ((fd =
		     open(lock_file, O_RDWR | O_CREAT | O_TRUNC,
			  S_IRUSR | S_IWUSR)) == -1) {
			ERR(sh, "Could not open direct %s at %s.", lock_name,
			    lock_file);
			return -1;
		}
	}
	if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
		ERR(sh, "Could not set close-on-exec for %s at %s.", lock_name,
		    lock_file);
		close(fd);
		return -1;
	}

	if (sh->timeout == 0) {
		/* return immediately */
		origtime.tv_sec = 0;
	} else {
		origtime.tv_sec = sh->timeout;
	}
	origtime.tv_usec = 0;
	do {
		curtime.tv_sec = 1;
		curtime.tv_usec = 0;
		if (flock(fd, LOCK_EX | LOCK_NB) == 0) {
			got_lock = 1;
			break;
		} else if (errno != EAGAIN) {
			ERR(sh, "Error obtaining direct %s at %s.", lock_name,
			    lock_file);
			close(fd);
			return -1;
		}
		if (origtime.tv_sec > 0 || sh->timeout == -1) {
			if (select(0, NULL, NULL, NULL, &curtime) == -1) {
				if (errno == EINTR) {
					continue;
				}
				ERR(sh,
				    "Error while waiting to get direct %s at %s.",
				    lock_name, lock_file);
				close(fd);
				return -1;
			}
			origtime.tv_sec--;
		}
	} while (origtime.tv_sec > 0 || sh->timeout == -1);
	if (!got_lock) {
		ERR(sh, "Could not get direct %s at %s.", lock_name, lock_file);
		close(fd);
		return -1;
	}
	return fd;
}

/* Locking for the module store for transactions.  This is very basic
 * locking of the module store and doesn't do anything if the module
 * store is being manipulated with a program not using this library
 * (but the policy should prevent that).  Returns 0 on success, -1 if
 * it could not obtain a lock.
 */
int semanage_get_trans_lock(semanage_handle_t * sh)
{
	const char *lock_file = semanage_files[SEMANAGE_TRANS_LOCK];

	if (sh->u.direct.translock_file_fd >= 0)
		return 0;

	sh->u.direct.translock_file_fd =
	    semanage_get_lock(sh, "transaction lock", lock_file);
	if (sh->u.direct.translock_file_fd >= 0) {
		return 0;
	} else {
		return -1;
	}
}

/* Locking for the module store for active store reading; this also includes
 * the file containing the commit number.  This is very basic locking
 * of the module store and doesn't do anything if the module store is
 * being manipulated with a program not using this library (but the
 * policy should prevent that).	 Returns 0 on success, -1 if it could
 * not obtain a lock.
 */
int semanage_get_active_lock(semanage_handle_t * sh)
{
	const char *lock_file = semanage_files[SEMANAGE_READ_LOCK];

	if (sh->u.direct.activelock_file_fd >= 0)
		return 0;

	sh->u.direct.activelock_file_fd =
	    semanage_get_lock(sh, "read lock", lock_file);
	if (sh->u.direct.activelock_file_fd >= 0) {
		return 0;
	} else {
		return -1;
	}
}

/* Releases the transaction lock.  Does nothing if there was not one already
 * there. */
void semanage_release_trans_lock(semanage_handle_t * sh)
{
	int errsv = errno;
	if (sh->u.direct.translock_file_fd >= 0) {
		flock(sh->u.direct.translock_file_fd, LOCK_UN);
		close(sh->u.direct.translock_file_fd);
		sh->u.direct.translock_file_fd = -1;
	}
	errno = errsv;
}

/* Releases the read lock.  Does nothing if there was not one already
 * there. */
void semanage_release_active_lock(semanage_handle_t * sh)
{
	int errsv = errno;
	if (sh->u.direct.activelock_file_fd >= 0) {
		flock(sh->u.direct.activelock_file_fd, LOCK_UN);
		close(sh->u.direct.activelock_file_fd);
		sh->u.direct.activelock_file_fd = -1;
	}
	errno = errsv;
}

/* Read the current commit number from the commit number file which
 * the handle is pointing, resetting the file pointer afterwards.
 * Return it (a non-negative number), or -1 on error. */
int semanage_direct_get_serial(semanage_handle_t * sh)
{
	char buf[32];
	int fd, commit_number;
	ssize_t amount_read;
	const char *commit_filename;
	memset(buf, 0, sizeof(buf));

	if (sh->is_in_transaction) {
		commit_filename =
		    semanage_path(SEMANAGE_TMP, SEMANAGE_COMMIT_NUM_FILE);
	} else {
		commit_filename =
		    semanage_path(SEMANAGE_ACTIVE, SEMANAGE_COMMIT_NUM_FILE);
	}

	if ((fd = open(commit_filename, O_RDONLY)) == -1) {
		if (errno == ENOENT) {
			/* the commit number file does not exist yet,
			 * so assume that the number is 0 */
			errno = 0;
			return 0;
		} else {
			ERR(sh, "Could not open commit number file %s.",
			    commit_filename);
			return -1;
		}
	}

	amount_read = read(fd, buf, sizeof(buf));
	if (amount_read == -1) {
		ERR(sh, "Error while reading commit number from %s.",
		    commit_filename);
		commit_number = -1;
	} else if (sscanf(buf, "%d", &commit_number) != 1) {
		/* if nothing was read, assume that the commit number is 0 */
		commit_number = 0;
	} else if (commit_number < 0) {
		/* read file ought never have negative values */
		ERR(sh,
		    "Commit number file %s is corrupted; it should only contain a non-negative integer.",
		    commit_filename);
		commit_number = -1;
	}

	close(fd);
	return commit_number;
}

/* HIGHER LEVEL COMMIT FUNCTIONS */

/* Loads a module (or a base) from a fully-qualified 'filename' into a
 * newly allocated sepol_module_package_t structure and returns it in
 * '*package'.	Caller is responsible for destroying it afterwards via
 * sepol_module_package_destroy().  Returns 0 on success, -1 on error.
 */
static int semanage_load_module(semanage_handle_t * sh, const char *filename,
				sepol_module_package_t ** package)
{
	int retval = 0;
	FILE *fp;
	struct sepol_policy_file *pf = NULL;

	*package = NULL;
	if (sepol_module_package_create(package) == -1) {
		ERR(sh, "Out of memory!");
		return -1;
	}

	if (sepol_policy_file_create(&pf)) {
		ERR(sh, "Out of memory!");
		goto cleanup;
	}

	if ((fp = fopen(filename, "rb")) == NULL) {
		ERR(sh, "Could not open module file %s for reading.", filename);
		goto cleanup;
	}
	ssize_t size;
	char *data = NULL;

	if ((size = bunzip(sh, fp, &data)) > 0) {
		sepol_policy_file_set_mem(pf, data, size);
	} else {
		rewind(fp);
		__fsetlocking(fp, FSETLOCKING_BYCALLER);
		sepol_policy_file_set_fp(pf, fp);
	}
	sepol_policy_file_set_handle(pf, sh->sepolh);
	if (sepol_module_package_read(*package, pf, 0) == -1) {
		ERR(sh, "Error while reading from module file %s.", filename);
		fclose(fp);
		free(data);
		goto cleanup;
	}
	sepol_policy_file_free(pf);
	fclose(fp);
	free(data);
	return retval;

      cleanup:
	sepol_module_package_free(*package);
	*package = NULL;
	sepol_policy_file_free(pf);
	return -1;
}

/* Links all of the modules within the sandbox into the base module.
 * '*base' will point to the module package that contains everything
 * linked together (caller must call sepol_module_package_destroy() on
 * it afterwards).  '*mods' will be a list of module packages and
 * '*num_modules' will be the number of elements within '*mods'
 * (caller must destroy each element as well as the pointer itself.)
 * Both '*base' and '*mods' will be set to NULL upon entering this
 * function.  Returns 0 on success, -1 on error.
 */
int semanage_link_sandbox(semanage_handle_t * sh,
			  sepol_module_package_t ** base)
{
	const char *base_filename = NULL;
	char **module_filenames = NULL;
	int retval = -1, i;
	int num_modules = 0;
	sepol_module_package_t **mods = NULL;

	*base = NULL;

	/* first make sure that base module is readable */
	if ((base_filename =
	     semanage_path(SEMANAGE_TMP, SEMANAGE_BASE)) == NULL) {
		goto cleanup;
	}
	if (access(base_filename, R_OK) == -1) {
		ERR(sh, "Could not access sandbox base file %s.",
		    base_filename);
		goto cleanup;
	}

	/* get list of modules and load them */
	if (semanage_get_active_modules_names(sh, &module_filenames, &num_modules) ==
	    -1 || semanage_load_module(sh, base_filename, base) == -1) {
		goto cleanup;
	}
	if ((mods = calloc(num_modules, sizeof(*mods))) == NULL) {
		ERR(sh, "Out of memory!");
		num_modules = 0;
		goto cleanup;
	}
	for (i = 0; i < num_modules; i++) {
		if (semanage_load_module(sh, module_filenames[i], mods + i) ==
		    -1) {
			goto cleanup;
		}
	}

	if (sepol_link_packages(sh->sepolh, *base, mods, num_modules, 0) != 0) {
		ERR(sh, "Link packages failed");
		goto cleanup;
	}

	retval = 0;

      cleanup:
	for (i = 0; module_filenames != NULL && i < num_modules; i++) {
		free(module_filenames[i]);
	}
	free(module_filenames);
	for (i = 0; mods != NULL && i < num_modules; i++) {
		sepol_module_package_free(mods[i]);
	}
	free(mods);
	return retval;
}

/* Links only the base module within the sandbox into the base module.
 * '*base' will point to the module package that contains everything
 * linked together (caller must call sepol_module_package_destroy() on
 * it afterwards).  '*base' will be set to NULL upon entering this
 * function.  Returns 0 on success, -1 on error.
 */
int semanage_link_base(semanage_handle_t * sh,
			  sepol_module_package_t ** base)
{
	const char *base_filename = NULL;
	int retval = -1;

	*base = NULL;

	/* first make sure that base module is readable */
	if ((base_filename =
	     semanage_path(SEMANAGE_TMP, SEMANAGE_BASE)) == NULL) {
		goto cleanup;
	}
	if (access(base_filename, R_OK) == -1) {
		ERR(sh, "Could not access sandbox base file %s.",
		    base_filename);
		goto cleanup;
	}

	if (semanage_load_module(sh, base_filename, base) == -1) {
		goto cleanup;
	}

	retval = 0;

      cleanup:
	return retval;
}

/* 
 * Expands the policy contained within *base 
 */
int semanage_expand_sandbox(semanage_handle_t * sh,
			    sepol_module_package_t * base,
			    sepol_policydb_t ** policydb)
{

	struct sepol_policydb *out = NULL;
	int policyvers = sh->conf->policyvers;
	int expand_check = sh->conf->expand_check ? sh->modules_modified : 0;

	if (sepol_policydb_create(&out))
		goto err;

	sepol_set_expand_consume_base(sh->sepolh, 1);

	if (sepol_expand_module(sh->sepolh,
				sepol_module_package_get_policy(base), out, 0,
				expand_check)
	    == -1) {
		ERR(sh, "Expand module failed");
		goto err;
	}
	if (sepol_policydb_set_vers(out, policyvers)) {
		ERR(sh, "Unknown/Invalid policy version %d.", policyvers);
		goto err;
	}
	if (sh->conf->handle_unknown >= 0)
		sepol_policydb_set_handle_unknown(out, sh->conf->handle_unknown);

	*policydb = out;
	return STATUS_SUCCESS;

      err:
	sepol_policydb_free(out);
	return STATUS_ERR;
}

/**
 * Read the policy from the sandbox (kernel)
 */
int semanage_read_policydb(semanage_handle_t * sh, sepol_policydb_t * in)
{

	int retval = STATUS_ERR;
	const char *kernel_filename = NULL;
	struct sepol_policy_file *pf = NULL;
	FILE *infile = NULL;

	if ((kernel_filename =
	     semanage_path(SEMANAGE_ACTIVE, SEMANAGE_KERNEL)) == NULL) {
		goto cleanup;
	}
	if ((infile = fopen(kernel_filename, "r")) == NULL) {
		ERR(sh, "Could not open kernel policy %s for reading.",
		    kernel_filename);
		goto cleanup;
	}
	__fsetlocking(infile, FSETLOCKING_BYCALLER);
	if (sepol_policy_file_create(&pf)) {
		ERR(sh, "Out of memory!");
		goto cleanup;
	}
	sepol_policy_file_set_fp(pf, infile);
	sepol_policy_file_set_handle(pf, sh->sepolh);
	if (sepol_policydb_read(in, pf) == -1) {
		ERR(sh, "Error while reading kernel policy from %s.",
		    kernel_filename);
		goto cleanup;
	}
	retval = STATUS_SUCCESS;

      cleanup:
	if (infile != NULL) {
		fclose(infile);
	}
	sepol_policy_file_free(pf);
	return retval;
}
/**
 * Writes the final policy to the sandbox (kernel)
 */
int semanage_write_policydb(semanage_handle_t * sh, sepol_policydb_t * out)
{

	int retval = STATUS_ERR;
	const char *kernel_filename = NULL;
	struct sepol_policy_file *pf = NULL;
	FILE *outfile = NULL;

	if ((kernel_filename =
	     semanage_path(SEMANAGE_TMP, SEMANAGE_KERNEL)) == NULL) {
		goto cleanup;
	}
	if ((outfile = fopen(kernel_filename, "wb")) == NULL) {
		ERR(sh, "Could not open kernel policy %s for writing.",
		    kernel_filename);
		goto cleanup;
	}
	__fsetlocking(outfile, FSETLOCKING_BYCALLER);
	if (sepol_policy_file_create(&pf)) {
		ERR(sh, "Out of memory!");
		goto cleanup;
	}
	sepol_policy_file_set_fp(pf, outfile);
	sepol_policy_file_set_handle(pf, sh->sepolh);
	if (sepol_policydb_write(out, pf) == -1) {
		ERR(sh, "Error while writing kernel policy to %s.",
		    kernel_filename);
		goto cleanup;
	}
	retval = STATUS_SUCCESS;

      cleanup:
	if (outfile != NULL) {
		fclose(outfile);
	}
	sepol_policy_file_free(pf);
	return retval;
}

/* Execute the module verification programs for each source module.
 * Returns 0 if every verifier returned success, -1 on error.
 */
int semanage_verify_modules(semanage_handle_t * sh,
			    char **module_filenames, int num_modules)
{
	int i, retval;
	semanage_conf_t *conf = sh->conf;
	if (conf->mod_prog == NULL) {
		return 0;
	}
	for (i = 0; i < num_modules; i++) {
		char *module = module_filenames[i];
		external_prog_t *e;
		for (e = conf->mod_prog; e != NULL; e = e->next) {
			if ((retval =
			     semanage_exec_prog(sh, e, module, "$<")) != 0) {
				return -1;
			}
		}
	}
	return 0;
}

/* Execute the linker verification programs for the linked (but not
 * expanded) base.  Returns 0 if every verifier returned success, -1
 * on error.
 */
int semanage_verify_linked(semanage_handle_t * sh)
{
	external_prog_t *e;
	semanage_conf_t *conf = sh->conf;
	const char *linked_filename =
	    semanage_path(SEMANAGE_TMP, SEMANAGE_LINKED);
	int retval = -1;
	if (conf->linked_prog == NULL) {
		return 0;
	}
	for (e = conf->linked_prog; e != NULL; e = e->next) {
		if (semanage_exec_prog(sh, e, linked_filename, "$<") != 0) {
			goto cleanup;
		}
	}
	retval = 0;
      cleanup:
	return retval;
}

/* Execute each of the kernel verification programs.  Returns 0 if
 * every verifier returned success, -1 on error.
 */
int semanage_verify_kernel(semanage_handle_t * sh)
{
	int retval = -1;
	const char *kernel_filename =
	    semanage_path(SEMANAGE_TMP, SEMANAGE_KERNEL);
	semanage_conf_t *conf = sh->conf;
	external_prog_t *e;
	if (conf->kernel_prog == NULL) {
		return 0;
	}
	for (e = conf->kernel_prog; e != NULL; e = e->next) {
		if (semanage_exec_prog(sh, e, kernel_filename, "$<") != 0) {
			goto cleanup;
		}
	}
	retval = 0;
      cleanup:
	return retval;
}

/********************* functions that sort file contexts *********************/

/* Free the given node. */
static void semanage_fc_node_destroy(semanage_file_context_node_t * x)
{
	free(x->path);
	free(x->file_type);
	free(x->context);
	free(x);
}

/* Free the linked list of nodes starting at the given node. */
static void semanage_fc_node_list_destroy(semanage_file_context_node_t * x)
{
	semanage_file_context_node_t *temp;

	while (x) {
		temp = x;
		x = x->next;
		semanage_fc_node_destroy(temp);
	}
}

/* Free the linked list of buckets (and their node lists) 
 * starting at the given bucket. */
static void semanage_fc_bucket_list_destroy(semanage_file_context_bucket_t * x)
{
	semanage_file_context_bucket_t *temp;

	while (x) {
		temp = x;
		x = x->next;
		semanage_fc_node_list_destroy(temp->data);
		free(temp);
	}
}

/* Compares two file contexts' regular expressions and returns:
 *    -1 if a is less specific than b
 *     0 if a and be are equally specific
 *     1 if a is more specific than b
 * The comparison is based on the following heuristics,
 *  in order from most important to least important, given a and b:
 *     If a is a regular expression and b is not,
 *      -> a is less specific than b.
 *     If a's stem length is shorter than b's stem length,
 *      -> a is less specific than b.
 *     If a's string length is shorter than b's string length,
 *      -> a is less specific than b.
 *     If a does not have a specified type and b does not,
 *      -> a is less specific than b.
 * FIXME: These heuristics are imperfect, but good enough for 
 * now.  A proper comparison would determine which (if either)
 * regular expression is a subset of the other.
 */
static int semanage_fc_compare(semanage_file_context_node_t * a,
			       semanage_file_context_node_t * b)
{
	int a_has_meta = (a->meta >= 0);
	int b_has_meta = (b->meta >= 0);

	/* Check to see if either a or b are regexes
	 *  and the other isn't. */
	if (a_has_meta && !b_has_meta)
		return -1;
	if (b_has_meta && !a_has_meta)
		return 1;

	/* Check to see if either a or b have a shorter stem
	 *  length than the other. */
	if (a->meta < b->meta)
		return -1;
	if (b->meta < a->meta)
		return 1;

	/* Check to see if either a or b have a shorter string
	 *  length than the other. */
	if (a->effective_len < b->effective_len)
		return -1;
	if (b->effective_len < a->effective_len)
		return 1;

	/* Check to see if either a or b has a specified type
	 *  and the other doesn't. */
	if (!a->file_type && b->file_type)
		return -1;
	if (!b->file_type && a->file_type)
		return 1;

	/* If none of the above conditions were satisfied, 
	 * then a and b are equally specific. */
	return 0;
}

/* Merges two sorted file context linked lists into a single sorted one.
 * The left list is assumed to represent nodes that came first in the original ordering. 
 * The final sorted list is returned.
 */
static semanage_file_context_node_t
    * semanage_fc_merge(semanage_file_context_node_t * left,
			semanage_file_context_node_t * right)
{
	semanage_file_context_node_t *head;
	semanage_file_context_node_t *current;
	semanage_file_context_node_t *tail;

	if (!left)
		return right;

	if (!right)
		return left;

	if (semanage_fc_compare(left, right) == 1) {
		head = tail = right;
		right = right->next;
	} else {
		head = tail = left;
		left = left->next;
	}

	while (left && right) {
		/* if left was more specific than right,
		 * insert right before left.  Otherwise leave order alone. */
		if (semanage_fc_compare(left, right) == 1) {
			current = right;
			right = right->next;
		} else {
			current = left;
			left = left->next;
		}

		tail = tail->next = current;
	}

	tail->next = (left != NULL) ? left : right;

	return head;
}

/* Sorts file contexts from least specific to most specific.
 * A bucket linked list is passed in.  Upon completion,
 * there is only one bucket (pointed to by master) that 
 * contains a linked list of all the file contexts in sorted order.
 * Explanation of the algorithm:
 *  This is a stable implementation of an iterative merge sort.
 *  Each bucket initially has a linked list of file contexts
 *   that are 1 node long.
 *  Each pass, buckets (and the nodes they contain) are merged 
 *   two at time.
 *  Buckets are merged until there is only one bucket left, 
 *   containing the list of file contexts, sorted.
 */
static void semanage_fc_merge_sort(semanage_file_context_bucket_t * master)
{
	semanage_file_context_bucket_t *current;
	semanage_file_context_bucket_t *temp;

	/* Loop until master is the only bucket left.
	 * When we stop master contains the sorted list. */
	while (master->next) {
		current = master;

		/* Merge buckets two-by-two. 
		 * If there is an odd number of buckets, the last 
		 * bucket will be left alone, which corresponds 
		 * to the operation of merging it with an empty bucket. */
		while (current) {
			if (current->next) {
				current->data =
				    semanage_fc_merge(current->data,
						      current->next->data);
				temp = current->next;
				current->next = current->next->next;

				/* Free the (now empty) second bucket.
				 * (This does not touch the node list
				 * in the bucket because it has been 
				 * shifted over to the first bucket. */
				free(temp);
			}
			current = current->next;
		}
	}
}

/* Compute the location of the first regular expression 
 *   meta character in the path of the given node, if it exists. 
 * On return:
 *     fc_node->meta = position of meta character, if it exists
 *			(-1 corresponds to no character)
 */
static void semanage_fc_find_meta(semanage_file_context_node_t * fc_node)
{
	int c = 0;
	int escape_chars = 0;

	fc_node->meta = -1;

	/* Note: this while loop has been adapted from
	 *  spec_hasMetaChars in matchpathcon.c from
	 *  libselinux-1.22. */
	while (fc_node->path[c] != '\0') {
		switch (fc_node->path[c]) {
		case '.':
		case '^':
		case '$':
		case '?':
		case '*':
		case '+':
		case '|':
		case '[':
		case '(':
		case '{':
			fc_node->meta = c - escape_chars;
			return;
		case '\\':
			/* If an escape character is found,
			 *  skip the next character. */
			c++;
			escape_chars++;
			break;
		}

		c++;
	}
}

/* Replicates strchr, but limits search to buf_len characters. */
static char *semanage_strnchr(const char *buf, size_t buf_len, char c)
{
	size_t idx = 0;

	if (buf == NULL)
		return NULL;
	if (buf_len <= 0)
		return NULL;

	while (idx < buf_len) {
		if (buf[idx] == c)
			return (char *)buf + idx;
		idx++;
	}

	return NULL;
}

/* Returns a pointer to the end of line character in the given buffer.
 * Used in the context of a file context char buffer that we will be 
 * parsing and sorting.
 */
static char *semanage_get_line_end(const char *buf, size_t buf_len)
{
	char *line_end = NULL;

	if (buf == NULL)
		return NULL;
	if (buf_len <= 0)
		return NULL;

	line_end = semanage_strnchr(buf, buf_len, '\n');
	if (!line_end)
		line_end = semanage_strnchr(buf, buf_len, '\r');
	if (!line_end)
		line_end = semanage_strnchr(buf, buf_len, EOF);

	return line_end;
}

/*  Entry function for sorting a set of file context lines.
 *  Returns 0 on success, -1 on failure.
 *  Allocates a buffer pointed to by sorted_buf that contains the sorted lines.
 *  sorted_buf_len is set to the size of this buffer.
 *  This buffer is guaranteed to have a final \0 character. 
 *  This buffer must be released by the caller.
 */
int semanage_fc_sort(semanage_handle_t * sh, const char *buf, size_t buf_len,
		     char **sorted_buf, size_t * sorted_buf_len)
{
	size_t start, finish, regex_len, type_len, context_len;
	size_t line_len, buf_remainder, i;
	ssize_t sanity_check;
	const char *line_buf, *line_end;
	char *sorted_buf_pos;
	int escape_chars, just_saw_escape;

	semanage_file_context_node_t *temp;
	semanage_file_context_node_t *head;
	semanage_file_context_node_t *current;
	semanage_file_context_bucket_t *master;
	semanage_file_context_bucket_t *bcurrent;

	i = 0;

	if (sh == NULL) {
		return -1;
	}
	if (buf == NULL) {
		ERR(sh, "Received NULL buffer.");
		return -1;
	}
	if (buf_len <= 0) {
		ERR(sh, "Received buffer of length 0.");
		return -1;
	}

	/* Initialize the head of the linked list 
	 * that will contain a node for each file context line. */
	head = current =
	    (semanage_file_context_node_t *) calloc(1,
						    sizeof
						    (semanage_file_context_node_t));
	if (!head) {
		ERR(sh, "Failure allocating memory.");
		return -1;
	}

	/* Parse the char buffer into a semanage_file_context_node_t linked list. */
	line_buf = buf;
	buf_remainder = buf_len;
	while ((line_end = semanage_get_line_end(line_buf, buf_remainder))) {
		line_len = line_end - line_buf + 1;
		sanity_check = buf_remainder - line_len;
		buf_remainder = buf_remainder - line_len;

		if (sanity_check < 0) {
			ERR(sh, "Failure parsing file context buffer.");
			semanage_fc_node_list_destroy(head);
			return -1;
		}

		if (line_len == 0 || line_len == 1) {
			line_buf = line_end + 1;
			continue;
		}

		/* Skip the whitespace at the front of the line. */
		for (i = 0; i < line_len; i++) {
			if (!isspace(line_buf[i]))
				break;
		}

		/* Check for a blank line. */
		if (i >= line_len) {
			line_buf = line_end + 1;
			continue;
		}

		/* Check if the line is a comment. */
		if (line_buf[i] == '#') {
			line_buf = line_end + 1;
			continue;
		}

		/* Allocate a new node. */
		temp =
		    (semanage_file_context_node_t *) calloc(1,
							    sizeof
							    (semanage_file_context_node_t));
		if (!temp) {
			ERR(sh, "Failure allocating memory.");
			semanage_fc_node_list_destroy(head);
			return -1;
		}
		temp->next = NULL;

		/* Extract the regular expression from the line. */
		escape_chars = 0;
		just_saw_escape = 0;
		start = i;
		while (i < line_len && (!isspace(line_buf[i]))) {
			if (line_buf[i] == '\\') {
				if (!just_saw_escape) {
					escape_chars++;
					just_saw_escape = 1;
				} else {
					/* We're looking at an escaped 
					   escape. Reset our flag. */
					just_saw_escape = 0;
				}
			} else {
				just_saw_escape = 0;
			}
			i++;
		}
		finish = i;
		regex_len = finish - start;

		if (regex_len == 0) {
			ERR(sh,
			    "WARNING: semanage_fc_sort: Regex of length 0.");
			semanage_fc_node_destroy(temp);
			line_buf = line_end + 1;
			continue;
		}

		temp->path = (char *)strndup(&line_buf[start], regex_len);
		if (!temp->path) {
			ERR(sh, "Failure allocating memory.");
			semanage_fc_node_destroy(temp);
			semanage_fc_node_list_destroy(head);
			return -1;
		}

		/* Skip the whitespace after the regular expression. */
		for (; i < line_len; i++) {
			if (!isspace(line_buf[i]))
				break;
		}
		if (i == line_len) {
			ERR(sh,
			    "WARNING: semanage_fc_sort: Incomplete context. %s", temp->path);
			semanage_fc_node_destroy(temp);
			line_buf = line_end + 1;
			continue;
		}

		/* Extract the inode type from the line (if it exists). */
		if (line_buf[i] == '-') {
			type_len = 2;	/* defined as '--', '-d', '-f', etc. */

			if (i + type_len >= line_len) {
				ERR(sh,
				    "WARNING: semanage_fc_sort: Incomplete context. %s", temp->path);
				semanage_fc_node_destroy(temp);
				line_buf = line_end + 1;
				continue;
			}

			/* Record the inode type. */
			temp->file_type =
			    (char *)strndup(&line_buf[i], type_len);
			if (!temp->file_type) {
				ERR(sh, "Failure allocating memory.");
				semanage_fc_node_destroy(temp);
				semanage_fc_node_list_destroy(head);
				return -1;
			}

			i += type_len;

			/* Skip the whitespace after the type. */
			for (; i < line_len; i++) {
				if (!isspace(line_buf[i]))
					break;
			}
			if (i == line_len) {
				ERR(sh,
				    "WARNING: semanage_fc_sort: Incomplete context. %s", temp->path);
				semanage_fc_node_destroy(temp);
				line_buf = line_end + 1;
				continue;
			}
		} else {
			type_len = 0;	/* inode type did not exist in the file context */
		}

		/* Extract the context from the line. */
		start = i;
		while (i < line_len && (!isspace(line_buf[i])))
			i++;
		finish = i;
		context_len = finish - start;

		temp->context = (char *)strndup(&line_buf[start], context_len);
		if (!temp->context) {
			ERR(sh, "Failure allocating memory.");
			semanage_fc_node_destroy(temp);
			semanage_fc_node_list_destroy(head);
			return -1;
		}

		/* Initialize the data about the file context. */
		temp->path_len = regex_len;
		temp->effective_len = regex_len - escape_chars;
		temp->type_len = type_len;
		temp->context_len = context_len;
		semanage_fc_find_meta(temp);

		/* Add this node to the end of the linked list. */
		current->next = temp;
		current = current->next;

		line_buf = line_end + 1;
	}

	/* Create the bucket linked list from the node linked list. */
	current = head->next;
	bcurrent = master = (semanage_file_context_bucket_t *)
	    calloc(1, sizeof(semanage_file_context_bucket_t));
	if (!master) {
		ERR(sh, "Failure allocating memory.");
		semanage_fc_node_list_destroy(head);
		return -1;
	}

	/* Free the head node, as it is no longer used. */
	semanage_fc_node_destroy(head);
	head = NULL;

	/* Place each node into a bucket. */
	while (current) {
		bcurrent->data = current;
		current = current->next;

		/* Detach the node in the bucket from the old list. */
		bcurrent->data->next = NULL;

		/* If we need another bucket, add one to the end. */
		if (current) {
			bcurrent->next = (semanage_file_context_bucket_t *)
			    calloc(1, sizeof(semanage_file_context_bucket_t));
			if (!(bcurrent->next)) {
				ERR(sh, "Failure allocating memory.");
				semanage_fc_bucket_list_destroy(master);
				return -1;
			}

			bcurrent = bcurrent->next;
		}
	}

	/* Sort the bucket list. */
	semanage_fc_merge_sort(master);

	/* First, calculate how much space we'll need for 
	 * the newly sorted block of data.  (We don't just
	 * use buf_len for this because we have extracted
	 * comments and whitespace.) */
	i = 0;
	current = master->data;
	while (current) {
		i += current->path_len + 1;	/* +1 for a tab */
		if (current->file_type) {
			i += current->type_len + 1;	/* +1 for a tab */
		}
		i += current->context_len + 1;	/* +1 for a newline */
		current = current->next;
	}
	i = i + 1;		/* +1 for trailing \0 */

	/* Allocate the buffer for the sorted list. */
	*sorted_buf = calloc(i, sizeof(char));
	if (!*sorted_buf) {
		ERR(sh, "Failure allocating memory.");
		semanage_fc_bucket_list_destroy(master);
		return -1;
	}
	*sorted_buf_len = i;

	/* Output the sorted semanage_file_context linked list to the char buffer. */
	sorted_buf_pos = *sorted_buf;
	current = master->data;
	while (current) {
		/* Output the path. */
		i = current->path_len + 1;	/* +1 for tab */
		snprintf(sorted_buf_pos, i + 1, "%s\t", current->path);
		sorted_buf_pos = sorted_buf_pos + i;

		/* Output the type, if there is one. */
		if (current->file_type) {
			i = strlen(current->file_type) + 1;	/* +1 for tab */
			snprintf(sorted_buf_pos, i + 1, "%s\t",
				 current->file_type);
			sorted_buf_pos = sorted_buf_pos + i;
		}

		/* Output the context. */
		i = strlen(current->context) + 1;	/* +1 for newline */
		snprintf(sorted_buf_pos, i + 1, "%s\n", current->context);
		sorted_buf_pos = sorted_buf_pos + i;

		current = current->next;
	}

	/* Clean up. */
	semanage_fc_bucket_list_destroy(master);

	/* Sanity check. */
	sorted_buf_pos++;
	if ((sorted_buf_pos - *sorted_buf) != (ssize_t) * sorted_buf_len) {
		ERR(sh, "Failure writing sorted buffer.");
		free(*sorted_buf);
		*sorted_buf = NULL;
		return -1;
	}

	return 0;
}

/********************* functions that sort netfilter contexts *********************/
#define NC_SORT_NAMES { "pre", "base", "module", "local", "post" }
#define NC_SORT_NAMES_LEN { 3, 4, 6, 5, 4 }
#define NC_SORT_NEL 5
static void semanage_nc_destroy_ruletab(semanage_netfilter_context_node_t *
					ruletab[NC_SORT_NEL][2])
{
	semanage_netfilter_context_node_t *curr, *next;
	int i;

	for (i = 0; i < NC_SORT_NEL; i++) {
		for (curr = ruletab[i][0]; curr != NULL; curr = next) {
			next = curr->next;
			free(curr->rule);
			free(curr);
		}
	}
}

/*  Entry function for sorting a set of netfilter context lines.
 *  Returns 0 on success, -1 on failure.
 *  Allocates a buffer pointed to by sorted_buf that contains the sorted lines.
 *  sorted_buf_len is set to the size of this buffer.
 *  This buffer is guaranteed to have a final \0 character. 
 *  This buffer must be released by the caller.
 */
int semanage_nc_sort(semanage_handle_t * sh, const char *buf, size_t buf_len,
		     char **sorted_buf, size_t * sorted_buf_len)
{

	/* parsing bits */
	const char *priority_names[] = NC_SORT_NAMES;
	const int priority_names_len[] = NC_SORT_NAMES_LEN;
	size_t line_len, buf_remainder, i, offset;
	const char *line_buf, *line_end;

	/* ruletab bits */
	/* keep track of the head (index 0) and tail (index 1) with this array */
	semanage_netfilter_context_node_t *ruletab[NC_SORT_NEL][2];
	semanage_netfilter_context_node_t *curr, *node;
	int priority;

	/* sorted buffer bits */
	char *sorted_buf_pos;
	size_t count;

	/* initialize ruletab */
	memset(ruletab, 0,
	       NC_SORT_NEL * 2 * sizeof(semanage_netfilter_context_node_t *));

	/* while lines to be read */
	line_buf = buf;
	buf_remainder = buf_len;
	while ((line_end = semanage_get_line_end(line_buf, buf_remainder))) {
		line_len = line_end - line_buf + 1;
		buf_remainder = buf_remainder - line_len;

		if (line_len == 0 || line_len == 1) {
			line_buf = line_end + 1;
			continue;
		}

		/* Skip the whitespace at the front of the line. */
		for (i = 0; i < line_len; i++) {
			if (!isspace(line_buf[i]))
				break;
		}

		/* Check for a blank line. */
		if (i >= line_len) {
			line_buf = line_end + 1;
			continue;
		}

		/* Check if the line is a comment. */
		if (line_buf[i] == '#') {
			line_buf = line_end + 1;
			continue;
		}

		/* extract priority */
		priority = -1;
		offset = 0;
		for (i = 0; i < NC_SORT_NEL; i++) {
			if (strncmp
			    (line_buf, priority_names[i],
			     priority_names_len[i]) == 0) {
				priority = i;
				offset = priority_names_len[i];
				break;
			}
		}

		if (priority < 0) {
			ERR(sh, "Netfilter context line missing priority.");
			semanage_nc_destroy_ruletab(ruletab);
			return -1;
		}

		/* skip over whitespace */
		for (; offset < line_len && isspace(line_buf[offset]);
		     offset++) ;

		/* load rule into node */
		node = (semanage_netfilter_context_node_t *)
		    malloc(sizeof(semanage_netfilter_context_node_t));
		if (!node) {
			ERR(sh, "Failure allocating memory.");
			semanage_nc_destroy_ruletab(ruletab);
			return -1;
		}

		node->rule =
		    (char *)strndup(line_buf + offset, line_len - offset);
		node->rule_len = line_len - offset;
		node->next = NULL;

		if (!node->rule) {
			ERR(sh, "Failure allocating memory.");
			free(node);
			semanage_nc_destroy_ruletab(ruletab);
			return -1;
		}

		/* add node to rule table */
		if (ruletab[priority][0] && ruletab[priority][1]) {
			/* add to end of list, update tail pointer */
			ruletab[priority][1]->next = node;
			ruletab[priority][1] = node;
		} else {
			/* this list is empty, make head and tail point to the node */
			ruletab[priority][0] = ruletab[priority][1] = node;
		}

		line_buf = line_end + 1;
	}

	/* First, calculate how much space we'll need for 
	 * the newly sorted block of data.  (We don't just
	 * use buf_len for this because we have extracted
	 * comments and whitespace.)  Start at 1 for trailing \0 */
	count = 1;
	for (i = 0; i < NC_SORT_NEL; i++)
		for (curr = ruletab[i][0]; curr != NULL; curr = curr->next)
			count += curr->rule_len;

	/* Allocate the buffer for the sorted list. */
	*sorted_buf = calloc(count, sizeof(char));
	if (!*sorted_buf) {
		ERR(sh, "Failure allocating memory.");
		semanage_nc_destroy_ruletab(ruletab);
		return -1;
	}
	*sorted_buf_len = count;

	/* write out rule buffer */
	sorted_buf_pos = *sorted_buf;
	for (i = 0; i < NC_SORT_NEL; i++) {
		for (curr = ruletab[i][0]; curr != NULL; curr = curr->next) {
			/* put rule into buffer */
			snprintf(sorted_buf_pos, curr->rule_len + 1, "%s\n", curr->rule);	/* +1 for newline */
			sorted_buf_pos = sorted_buf_pos + curr->rule_len;
		}
	}

	/* free ruletab */
	semanage_nc_destroy_ruletab(ruletab);

	return 0;
}
