/* Authors: Karl MacMillan <kmacmillan@tresys.com>
 *	    Joshua Brindle <jbrindle@tresys.com>
 *	    Jason Tang <jtang@tresys.com>
 *          Christopher Ashworth <cashworth@tresys.com>
 *          Chris PeBenito <cpebenito@tresys.com>
 *	    Caleb Case <ccase@tresys.com>
 *
 * Copyright (C) 2004-2006,2009 Tresys Technology, LLC
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
#include <libgen.h>

#include "debug.h"
#include "utilities.h"
#include "compressed_file.h"

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

/* relative path names to enum sandbox_paths for special files within
 * a sandbox */
static const char *semanage_sandbox_paths[SEMANAGE_STORE_NUM_PATHS] = {
	"",
	"/modules",
	"/policy.linked",
	"/homedir_template",
	"/file_contexts.template",
	"/commit_num",
	"/pkeys.local",
	"/ibendports.local",
	"/ports.local",
	"/interfaces.local",
	"/nodes.local",
	"/booleans.local",
	"/seusers.local",
	"/seusers.linked",
	"/users.local",
	"/users_extra.local",
	"/users_extra.linked",
	"/users_extra",
	"/disable_dontaudit",
	"/preserve_tunables",
	"/modules/disabled",
	"/modules_checksum",
	"/policy.kern",
	"/file_contexts.local",
	"/file_contexts.homedirs",
	"/file_contexts",
	"/seusers"
};

static char const * const semanage_final_prefix[SEMANAGE_FINAL_NUM] = {
	"/final",
	"",
};

static char *semanage_final[SEMANAGE_FINAL_NUM] = { NULL };
static char *semanage_final_suffix[SEMANAGE_FINAL_PATH_NUM] = { NULL };
static char *semanage_final_paths[SEMANAGE_FINAL_NUM][SEMANAGE_FINAL_PATH_NUM] = {{ NULL }};

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

	prefix_len = strlen(root);

	for (i = 0; i < SEMANAGE_NUM_FILES; i++) {
		len = (strlen(semanage_relative_files[i]) + prefix_len);
		semanage_files[i] = calloc(len + 1, sizeof(char));
		if (!semanage_files[i])
			return -1;
		sprintf(semanage_files[i], "%s%s", root,
			semanage_relative_files[i]);
	}

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

	if (!root)
		return -1;

	prefix_len = strlen(root);

	for (i = 0; i < SEMANAGE_NUM_STORES; i++) {
		for (j = 0; j < SEMANAGE_STORE_NUM_PATHS; j++) {
			len = prefix_len + strlen(semanage_store_paths[i])
			    + strlen(semanage_sandbox_paths[j]);
			semanage_paths[i][j] = calloc(len + 1, sizeof(char));
			if (!semanage_paths[i][j])
				goto cleanup;
			sprintf(semanage_paths[i][j], "%s%s%s", root,
				semanage_store_paths[i],
				semanage_sandbox_paths[j]);
		}
	}

      cleanup:
	return 0;
}

static int semanage_init_final(semanage_handle_t *sh, const char *prefix)
{
	assert(sh);
	assert(prefix);

	int status = 0;
	size_t len;
	const char *store_path = sh->conf->store_path;
	size_t store_len = strlen(store_path);

	/* SEMANAGE_FINAL_TMP */
	len = strlen(semanage_root()) +
	      strlen(prefix) +
	      strlen("/") +
	      strlen(semanage_final_prefix[SEMANAGE_FINAL_TMP]) +
	      store_len;
	semanage_final[SEMANAGE_FINAL_TMP] = malloc(len + 1);
	if (semanage_final[SEMANAGE_FINAL_TMP] == NULL) {
		status = -1;
		goto cleanup;
	}

	sprintf(semanage_final[SEMANAGE_FINAL_TMP],
		"%s%s%s/%s",
		semanage_root(),
		prefix,
		semanage_final_prefix[SEMANAGE_FINAL_TMP],
		store_path);

	/* SEMANAGE_FINAL_SELINUX */
	const char *selinux_root = selinux_path();
	len = strlen(semanage_root()) +
	      strlen(selinux_root) +
	      strlen(semanage_final_prefix[SEMANAGE_FINAL_SELINUX]) +
	      store_len;
	semanage_final[SEMANAGE_FINAL_SELINUX] = malloc(len + 1);
	if (semanage_final[SEMANAGE_FINAL_SELINUX] == NULL) {
		status = -1;
		goto cleanup;
	}

	sprintf(semanage_final[SEMANAGE_FINAL_SELINUX],
		"%s%s%s%s",
		semanage_root(),
		selinux_root,
		semanage_final_prefix[SEMANAGE_FINAL_SELINUX],
		store_path);

cleanup:
	if (status != 0) {
		int i;
		for (i = 0; i < SEMANAGE_FINAL_NUM; i++) {
			free(semanage_final[i]);
			semanage_final[i] = NULL;
		}
	}

	return status;
}

static int semanage_init_final_suffix(semanage_handle_t *sh)
{
	int ret = 0;
	int status = 0;
	char path[PATH_MAX];
	size_t offset = strlen(selinux_policy_root());

	semanage_final_suffix[SEMANAGE_FINAL_TOPLEVEL] = strdup("");
	if (semanage_final_suffix[SEMANAGE_FINAL_TOPLEVEL] == NULL) {
		ERR(sh, "Unable to allocate space for policy top level path.");
		status = -1;
		goto cleanup;
	}

	semanage_final_suffix[SEMANAGE_FC] =
		strdup(selinux_file_context_path() + offset);
	if (semanage_final_suffix[SEMANAGE_FC] == NULL) {
		ERR(sh, "Unable to allocate space for file context path.");
		status = -1;
		goto cleanup;
	}

	if (asprintf(&semanage_final_suffix[SEMANAGE_FC_BIN], "%s.bin",
		     semanage_final_suffix[SEMANAGE_FC]) < 0) {
		ERR(sh, "Unable to allocate space for file context path.");
		status = -1;
		goto cleanup;
	}

	semanage_final_suffix[SEMANAGE_FC_HOMEDIRS] =
		strdup(selinux_file_context_homedir_path() + offset);
	if (semanage_final_suffix[SEMANAGE_FC_HOMEDIRS] == NULL) {
		ERR(sh, "Unable to allocate space for file context home directory path.");
		status = -1;
		goto cleanup;
	}

	if (asprintf(&semanage_final_suffix[SEMANAGE_FC_HOMEDIRS_BIN], "%s.bin",
		     semanage_final_suffix[SEMANAGE_FC_HOMEDIRS]) < 0) {
		ERR(sh, "Unable to allocate space for file context home directory path.");
		status = -1;
		goto cleanup;
	}

	semanage_final_suffix[SEMANAGE_FC_LOCAL] =
		strdup(selinux_file_context_local_path() + offset);
	if (semanage_final_suffix[SEMANAGE_FC_LOCAL] == NULL) {
		ERR(sh, "Unable to allocate space for local file context path.");
		status = -1;
		goto cleanup;
	}

	if (asprintf(&semanage_final_suffix[SEMANAGE_FC_LOCAL_BIN], "%s.bin",
		     semanage_final_suffix[SEMANAGE_FC_LOCAL]) < 0) {
		ERR(sh, "Unable to allocate space for local file context path.");
		status = -1;
		goto cleanup;
	}

	semanage_final_suffix[SEMANAGE_NC] =
		strdup(selinux_netfilter_context_path() + offset);
	if (semanage_final_suffix[SEMANAGE_NC] == NULL) {
		ERR(sh, "Unable to allocate space for netfilter context path.");
		status = -1;
		goto cleanup;
	}

	semanage_final_suffix[SEMANAGE_SEUSERS] =
		strdup(selinux_usersconf_path() + offset);
	if (semanage_final_suffix[SEMANAGE_SEUSERS] == NULL) {
		ERR(sh, "Unable to allocate space for userconf path.");
		status = -1;
		goto cleanup;
	}

	ret = snprintf(path,
		       sizeof(path),
		       "%s.%d",
		       selinux_binary_policy_path() + offset,
		       sh->conf->policyvers);
	if (ret < 0 || ret >= (int)sizeof(path)) {
		ERR(sh, "Unable to compose policy binary path.");
		status = -1;
		goto cleanup;
	}

	semanage_final_suffix[SEMANAGE_KERNEL] = strdup(path);
	if (semanage_final_suffix[SEMANAGE_KERNEL] == NULL) {
		ERR(sh, "Unable to allocate space for policy binary path.");
		status = -1;
		goto cleanup;
	}

cleanup:
	if (status != 0) {
		int i;
		for (i = 0; i < SEMANAGE_FINAL_PATH_NUM; i++) {
			free(semanage_final_suffix[i]);
			semanage_final_suffix[i] = NULL;
		}
	}

	return status;
}

/* Initialize final paths. */
static int semanage_init_final_paths(semanage_handle_t *sh)
{
	int status = 0;
	int i, j;
	size_t len;

	for (i = 0; i < SEMANAGE_FINAL_NUM; i++) {
		for (j = 0; j < SEMANAGE_FINAL_PATH_NUM; j++) {
			len = 	  strlen(semanage_final[i])
				+ strlen(semanage_final_suffix[j]);

			semanage_final_paths[i][j] = malloc(len + 1);
			if (semanage_final_paths[i][j] == NULL) {
				ERR(sh, "Unable to allocate space for policy final path.");
				status = -1;
				goto cleanup;
			}

			sprintf(semanage_final_paths[i][j],
				"%s%s",
				semanage_final[i],
				semanage_final_suffix[j]);
		}
	}

cleanup:
	if (status != 0) {
		for (i = 0; i < SEMANAGE_FINAL_NUM; i++) {
			for (j = 0; j < SEMANAGE_FINAL_PATH_NUM; j++) {
				free(semanage_final_paths[i][j]);
				semanage_final_paths[i][j] = NULL;
			}
		}
	}

	return status;
}

/* THIS MUST BE THE FIRST FUNCTION CALLED IN THIS LIBRARY.  If the
 * library has nnot been initialized yet then call the functions that
 * initialize the path variables.  This function does nothing if it
 * was previously called and that call was successful.  Return 0 on
 * success, -1 on error.
 *
 * Note that this function is NOT thread-safe.
 */
int semanage_check_init(semanage_handle_t *sh, const char *prefix)
{
	int rc;
	if (semanage_paths_initialized == 0) {
		char root[PATH_MAX];

		rc = snprintf(root,
			      sizeof(root),
			      "%s%s/%s",
			      semanage_root(),
			      prefix,
			      sh->conf->store_path);
		if (rc < 0 || rc >= (int)sizeof(root))
			return -1;

		rc = semanage_init_paths(root);
		if (rc)
			return rc;

		rc = semanage_init_store_paths(root);
		if (rc)
			return rc;

		rc = semanage_init_final(sh, prefix);
		if (rc)
			return rc;

		rc = semanage_init_final_suffix(sh);
		if (rc)
			return rc;

		rc = semanage_init_final_paths(sh);
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

/* Given a store location (tmp or selinux) and a definition
 * number, return a fully-qualified path to that file or directory.
 * The caller must not alter the string returned (and hence why this
 * function return type is const).
 *
 * This function shall never return a NULL, assuming that
 * semanage_check_init() was previously called.
 */
const char *semanage_final_path(enum semanage_final_defs store,
				enum semanage_final_path_defs path_name)
{
	assert(semanage_final_paths[store][path_name]);
	return semanage_final_paths[store][path_name];
}

/* Return a fully-qualified path + filename to the semanage
 * configuration file. If semanage.conf file in the semanage
 * root is cannot be read, use the default semanage.conf as a
 * fallback.
 *
 * The caller is responsible for freeing the returned string.
 */
char *semanage_conf_path(void)
{
	char *semanage_conf = NULL;
	int len;
	struct stat sb;

	len = strlen(semanage_root()) + strlen(selinux_path()) + strlen(SEMANAGE_CONF_FILE);
	semanage_conf = calloc(len + 1, sizeof(char));
	if (!semanage_conf)
		return NULL;
	snprintf(semanage_conf, len + 1, "%s%s%s", semanage_root(), selinux_path(),
		 SEMANAGE_CONF_FILE);

	if (stat(semanage_conf, &sb) != 0 && errno == ENOENT) {
		snprintf(semanage_conf, len + 1, "%s%s", selinux_path(), SEMANAGE_CONF_FILE);
	}

	return semanage_conf;
}

/**************** functions that create module store ***************/

/* Check that the semanage store exists.  If 'create' is non-zero then
 * create the directories.  Returns 0 if module store exists (either
 * already or just created), -1 if does not exist or could not be
 * read, or -2 if it could not create the store. */
int semanage_create_store(semanage_handle_t * sh, int create)
{
	struct stat sb;
	const char *path = semanage_files[SEMANAGE_ROOT];
	int fd;
	mode_t mask;

	if (stat(path, &sb) == -1) {
		if (errno == ENOENT && create) {
			mask = umask(0077);
			if (mkdir(path, S_IRWXU) == -1) {
				umask(mask);
				ERR(sh, "Could not create module store at %s.",
				    path);
				return -2;
			}
			umask(mask);
		} else {
			if (create)
				ERR(sh,
				    "Could not read from module store at %s.",
				    path);
			return -1;
		}
	} else {
		if (!S_ISDIR(sb.st_mode)) {
			ERR(sh,
			    "Module store at %s is not a directory.",
			    path);
			return -1;
		}
	}
	path = semanage_path(SEMANAGE_ACTIVE, SEMANAGE_TOPLEVEL);
	if (stat(path, &sb) == -1) {
		if (errno == ENOENT && create) {
			mask = umask(0077);
			if (mkdir(path, S_IRWXU) == -1) {
				umask(mask);
				ERR(sh,
				    "Could not create module store, active subdirectory at %s.",
				    path);
				return -2;
			}
			umask(mask);
		} else {
			ERR(sh,
			    "Could not read from module store, active subdirectory at %s.",
			    path);
			return -1;
		}
	} else {
		if (!S_ISDIR(sb.st_mode)) {
			ERR(sh,
			    "Module store active subdirectory at %s is not a directory.",
			    path);
			return -1;
		}
	}
	path = semanage_path(SEMANAGE_ACTIVE, SEMANAGE_MODULES);
	if (stat(path, &sb) == -1) {
		if (errno == ENOENT && create) {
			mask = umask(0077);
			if (mkdir(path, S_IRWXU) == -1) {
				umask(mask);
				ERR(sh,
				    "Could not create module store, active modules subdirectory at %s.",
				    path);
				return -2;
			}
			umask(mask);
		} else {
			ERR(sh,
			    "Could not read from module store, active modules subdirectory at %s.",
			    path);
			return -1;
		}
	} else {
		if (!S_ISDIR(sb.st_mode)) {
			ERR(sh,
			    "Module store active modules subdirectory at %s is not a directory.",
			    path);
			return -1;
		}
	}
	path = semanage_files[SEMANAGE_READ_LOCK];
	if (stat(path, &sb) == -1) {
		if (errno == ENOENT && create) {
			mask = umask(0077);
			if ((fd = creat(path, S_IRUSR | S_IWUSR)) == -1) {
				umask(mask);
				ERR(sh, "Could not create lock file at %s.",
				    path);
				return -2;
			}
			umask(mask);
			close(fd);
		} else {
			ERR(sh, "Could not read lock file at %s.", path);
			return -1;
		}
	} else {
		if (!S_ISREG(sb.st_mode)) {
			ERR(sh, "Object at %s is not a lock file.", path);
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

static int semanage_rename(semanage_handle_t * sh, const char *tmp, const char *dst);
int semanage_remove_directory(const char *path);
static int semanage_copy_dir_flags(const char *src, const char *dst, int flag);

/* Callback used by scandir() to select files. */
static int semanage_filename_select(const struct dirent *d)
{
	if (d->d_name[0] == '.'
	    && (d->d_name[1] == '\0'
		|| (d->d_name[1] == '.' && d->d_name[2] == '\0')))
		return 0;
	return 1;
}

/* Copies a file from src to dst.  If dst already exists then
 * overwrite it.  Returns 0 on success, -1 on error. */
int semanage_copy_file(const char *src, const char *dst, mode_t mode,
		bool syncrequired)
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
		if (write(out, buf, amount_read) != amount_read) {
			if (errno)
				errsv = errno;
			else
				errsv = EIO;
			retval = -1;
		}
	}
	if (amount_read < 0) {
		errsv = errno;
		retval = -1;
	}
	close(in);
	if (syncrequired && fsync(out) < 0) {
		errsv = errno;
		retval = -1;
	}
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

static int semanage_rename(semanage_handle_t * sh, const char *src, const char *dst) {
	int retval;

	retval = rename(src, dst);
	if (retval == 0 || errno != EXDEV)
		return retval;

	/* we can't use rename() due to filesystem limitation, lets try to copy files manually */
	WARN(sh, "WARNING: rename(%s, %s) failed: %s, fall back to non-atomic semanage_copy_dir_flags()",
		 src, dst, strerror(errno));
	if (semanage_copy_dir_flags(src, dst, 1) == -1) {
		return -1;
	}
	return semanage_remove_directory(src);
}

/* Copies all of the files from src to dst, recursing into
 * subdirectories.  Returns 0 on success, -1 on error. */
static int semanage_copy_dir(const char *src, const char *dst)
{
	return semanage_copy_dir_flags(src, dst, 1);
}

/* Copies all of the dirs from src to dst, recursing into
 * subdirectories. If flag == 1, then copy regular files as
 * well. Returns 0 on success, -1 on error. */
static int semanage_copy_dir_flags(const char *src, const char *dst, int flag)
{
	int i, len = 0, retval = -1;
	struct stat sb;
	struct dirent **names = NULL;
	char path[PATH_MAX], path2[PATH_MAX];
	mode_t mask;

	if ((len = scandir(src, &names, semanage_filename_select, NULL)) == -1) {
		fprintf(stderr, "Could not read the contents of %s: %s\n", src, strerror(errno));
		return -1;
	}

	if (stat(dst, &sb) != 0) {
		mask = umask(0077);
		if (mkdir(dst, S_IRWXU) != 0) {
			umask(mask);
			fprintf(stderr, "Could not create %s: %s\n", dst, strerror(errno));
			goto cleanup;
		}
		umask(mask);
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
			mask = umask(0077);
			if (mkdir(path2, 0700) == -1 ||
			    semanage_copy_dir_flags(path, path2, flag) == -1) {
				umask(mask);
				goto cleanup;
			}
			umask(mask);
		} else if (S_ISREG(sb.st_mode) && flag == 1) {
			mask = umask(0077);
			if (semanage_copy_file(path, path2, sb.st_mode,
						false) < 0) {
				umask(mask);
				goto cleanup;
			}
			umask(mask);
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
		char s[PATH_MAX];
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

int semanage_mkpath(semanage_handle_t *sh, const char *path)
{
	char fn[PATH_MAX];
	char *c;
	int rc = 0;

	if (strlen(path) >= PATH_MAX) {
		return -1;
	}

	for (c = strcpy(fn, path) + 1; *c != '\0'; c++) {
		if (*c != '/') {
			continue;
		}

		*c = '\0';
		rc = semanage_mkdir(sh, fn);
		if (rc < 0) {
			goto cleanup;
		}
		*c = '/';
	}
	rc = semanage_mkdir(sh, fn);

cleanup:
	return rc;
}

int semanage_mkdir(semanage_handle_t *sh, const char *path)
{
	int status = 0;
	struct stat sb;
	mode_t mask;

	/* check if directory already exists */
	if (stat(path, &sb) != 0) {
		/* make the modules directory */
		mask = umask(0077);
		if (mkdir(path, S_IRWXU) != 0) {
			umask(mask);
			ERR(sh, "Cannot make directory at %s", path);
			status = -1;
			goto cleanup;

		}
		umask(mask);
	}
	else {
		/* check that it really is a directory */
		if (!S_ISDIR(sb.st_mode)) {
			ERR(sh, "Directory path taken by non-directory file at %s.", path);
			status = -1;
			goto cleanup;
		}
	}

cleanup:
	return status;
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
	mode_t mask;

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

	mask = umask(0077);
	if (mkdir(sandbox, S_IRWXU) == -1 ||
	    semanage_copy_dir(semanage_path(SEMANAGE_ACTIVE, SEMANAGE_TOPLEVEL),
			      sandbox) == -1) {
		umask(mask);
		ERR(sh, "Could not copy files to sandbox %s.", sandbox);
		goto cleanup;
	}
	umask(mask);
	return 0;

      cleanup:
	errsv = errno;
	semanage_remove_directory(sandbox);
	errno = errsv;
	return -1;
}

/* Create final temporary space. Returns -1 on error 0 on success. */
int semanage_make_final(semanage_handle_t *sh)
{
	int status = 0;
	int ret = 0;
	char fn[PATH_MAX];

	/* Create tmp dir if it does not exist. */
	ret = snprintf(fn,
		       sizeof(fn),
		       "%s%s%s",
		       semanage_root(),
		       sh->conf->store_root_path,
		       semanage_final_prefix[SEMANAGE_FINAL_TMP]);
	if (ret < 0 || ret >= (int)sizeof(fn)) {
		ERR(sh, "Unable to compose the final tmp path.");
		status = -1;
		goto cleanup;
	}

	ret = semanage_mkdir(sh, fn);
	if (ret != 0) {
		ERR(sh, "Unable to create temporary directory for final files at %s", fn);
		status = -1;
		goto cleanup;
	}

	/* Delete store specific dir if it exists. */
	ret = semanage_remove_directory(
		semanage_final_path(SEMANAGE_FINAL_TMP,
				    SEMANAGE_FINAL_TOPLEVEL));
	if (ret < -1) {
		status = -1;
		goto cleanup;
	}

	// Build final directory structure
	int i;
	for (i = 1; i < SEMANAGE_FINAL_PATH_NUM; i++) {
		if (strlen(semanage_final_path(SEMANAGE_FINAL_TMP, i)) >= sizeof(fn)) {
			ERR(sh, "Unable to compose the final paths.");
			status = -1;
			goto cleanup;
		}
		strcpy(fn, semanage_final_path(SEMANAGE_FINAL_TMP, i));
		ret = semanage_mkpath(sh, dirname(fn));
		if (ret < 0) {
			status = -1;
			goto cleanup;
		}
	}

cleanup:
	return status;
}

/* qsort comparison function for semanage_get_active_modules. */
static int semanage_get_active_modules_cmp(const void *a, const void *b)
{
	semanage_module_info_t *aa = (semanage_module_info_t *)a;
	semanage_module_info_t *bb = (semanage_module_info_t *)b;

	return strcmp(aa->name, bb->name);
}

int semanage_get_cil_paths(semanage_handle_t * sh,
				semanage_module_info_t *modinfos,
				int num_modinfos,
				char *** filenames)
{
	char path[PATH_MAX];
	char **names = NULL;

	int ret;
	int status = 0;
	int i = 0;

	names = calloc(num_modinfos, sizeof(*names));
	if (names == NULL) {
		ERR(sh, "Error allocating space for filenames.");
		return -1;
	}

	for (i = 0; i < num_modinfos; i++) {
		ret = semanage_module_get_path(
				sh,
				&modinfos[i],
				SEMANAGE_MODULE_PATH_CIL,
				path,
				sizeof(path));
		if (ret != 0) {
			status = -1;
			goto cleanup;
		}

		names[i] = strdup(path);

		if (names[i] == NULL) {
			status = -1;
			goto cleanup;
		}
	}

cleanup:
	if (status != 0) {
		for (i = 0; i < num_modinfos; i++) {
			free(names[i]);
		}
		free(names);
	} else {
		*filenames = names;
	}

	return status;
}

/* Scans the modules directory for the current semanage handler.  This
 * might be the active directory or sandbox, depending upon if the
 * handler has a transaction lock.  Allocates and fills in *modinfos
 * with an array of module infos; length of array is stored in
 * *num_modules. The caller is responsible for free()ing *modinfos and its
 * individual elements.	 Upon success returns 0, -1 on error.
 */
int semanage_get_active_modules(semanage_handle_t * sh,
				semanage_module_info_t ** modinfo,
				int *num_modules)
{
	assert(sh);
	assert(modinfo);
	assert(num_modules);
	*modinfo = NULL;
	*num_modules = 0;

	int status = 0;
	int ret = 0;

	int i = 0;
	int j = 0;

	semanage_list_t *list = NULL;
	semanage_list_t *found = NULL;

	semanage_module_info_t *all_modinfos = NULL;
	int all_modinfos_len = 0;

	void *tmp = NULL;

	/* get all modules */
	ret = semanage_module_list_all(sh, &all_modinfos, &all_modinfos_len);
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

	if (all_modinfos_len == 0) {
		goto cleanup;
	}

	/* allocate enough for worst case */
	(*modinfo) = calloc(all_modinfos_len, sizeof(**modinfo));
	if ((*modinfo) == NULL) {
		ERR(sh, "Error allocating space for module information.");
		status = -1;
		goto cleanup;
	}

	/* for each highest priority, enabled module get its path */
	semanage_list_destroy(&list);
	j = 0;
	for (i = 0; i < all_modinfos_len; i++) {
		/* check if enabled */
		if (all_modinfos[i].enabled != 1) continue;

		/* check if we've seen this before (i.e. highest priority) */
		found = semanage_list_find(list, all_modinfos[i].name);
		if (found == NULL) {
			ret = semanage_list_push(&list, all_modinfos[i].name);
			if (ret != 0) {
				ERR(sh, "Failed to add module name to list of known names.");
				status = -1;
				goto cleanup;
			}
		}
		else continue;

		if (semanage_module_info_clone(sh, &all_modinfos[i], &(*modinfo)[j]) != 0) {
			status = -1;
			goto cleanup;
		}

		j += 1;
	}

	*num_modules = j;

	if (j == 0) {
		free(*modinfo);
		*modinfo = NULL;
		goto cleanup;
	}

	/* realloc the array to its min size */
	tmp = realloc(*modinfo, j * sizeof(**modinfo));
	if (tmp == NULL) {
		ERR(sh, "Error allocating space for filenames.");
		status = -1;
		goto cleanup;
	}
	*modinfo = tmp;

	/* sort array on module name */
	qsort(*modinfo,
	      *num_modules,
	      sizeof(**modinfo),
	      semanage_get_active_modules_cmp);

cleanup:
	semanage_list_destroy(&list);

	for (i = 0; i < all_modinfos_len; i++) {
		semanage_module_info_destroy(sh, &all_modinfos[i]);
	}
	free(all_modinfos);

	if (status != 0) {
		for (i = 0; i < j; i++) {
			semanage_module_info_destroy(sh, &(*modinfo)[i]);
		}
		free(*modinfo);
	}

	return status;
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
	size_t t_len;
	char *new_s;

	if (t == NULL) {
		return s;
	}
	t_len = strlen(t);
	new_s = realloc(s, s_len + t_len + 1);
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
	 * respecting quotes and other special characters */
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
						if (rc)
							goto cleanup;
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
		if (rc)
			goto cleanup;
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

	fc = open(semanage_path(SEMANAGE_TMP, SEMANAGE_STORE_FC),
		  O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fc < 0) {
		ERR(sh, "Could not open %s for writing.",
		    semanage_path(SEMANAGE_TMP, SEMANAGE_STORE_FC));
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
				    semanage_path(SEMANAGE_TMP, SEMANAGE_STORE_FC));
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
	struct stat sb;

	if (stat(path, &sb) < 0) {
		if (errno != ENOENT) {
			ERR(sh, "Unable to access %s: %s\n", path, strerror(errno));
			return -1;
		}

		return 0;
	}

	if ((r = semanage_exec_prog(sh, sh->conf->sefcontext_compile, path, "")) != 0) {
		ERR(sh, "sefcontext_compile returned error code %d. Compiling %s", r, path);
		return -1;
	}

	return 0;
}

static int semanage_validate_and_compile_fcontexts(semanage_handle_t * sh)
{
	int status = -1;

	if (sh->do_check_contexts) {
		int ret;
		ret = semanage_exec_prog(
			sh,
			sh->conf->setfiles,
			semanage_final_path(SEMANAGE_FINAL_TMP,
					    SEMANAGE_KERNEL),
			semanage_final_path(SEMANAGE_FINAL_TMP,
					    SEMANAGE_FC));
		if (ret != 0) {
			ERR(sh, "setfiles returned error code %d.", ret);
			goto cleanup;
		}
	}

	if (sefcontext_compile(sh,
		    semanage_final_path(SEMANAGE_FINAL_TMP, SEMANAGE_FC)) != 0) {
		goto cleanup;
	}

	if (sefcontext_compile(sh,
		    semanage_final_path(SEMANAGE_FINAL_TMP, SEMANAGE_FC_LOCAL)) != 0) {
		goto cleanup;
	}

	if (sefcontext_compile(sh,
		    semanage_final_path(SEMANAGE_FINAL_TMP, SEMANAGE_FC_HOMEDIRS)) != 0) {
		goto cleanup;
	}

	status = 0;
cleanup:
	return status;
}

/* Load the contexts of the final tmp into the final selinux directory.
 * Return 0 on success, -3 on error.
 */
static int semanage_install_final_tmp(semanage_handle_t * sh)
{
	int status = -3;
	int ret = 0;
	int i = 0;
	const char *src = NULL;
	const char *dst = NULL;
	struct stat sb;
	char fn[PATH_MAX];

	/* For each of the final files install it if it exists.
	 * i = 1 to avoid copying the top level directory.
	 */
	for (i = 1; i < SEMANAGE_FINAL_PATH_NUM; i++) {
		src = semanage_final_path(SEMANAGE_FINAL_TMP, i);
		dst = semanage_final_path(SEMANAGE_FINAL_SELINUX, i);

		/* skip file if src doesn't exist */
		if (stat(src, &sb) != 0) continue;

		/* skip genhomedircon if configured */
		if (sh->conf->disable_genhomedircon &&
		    i == SEMANAGE_FC_HOMEDIRS) continue;

		if (strlen(dst) >= sizeof(fn)) {
			ERR(sh, "Unable to compose the final paths.");
			status = -1;
			goto cleanup;
		}
		strcpy(fn, dst);
		ret = semanage_mkpath(sh, dirname(fn));
		if (ret < 0) {
			goto cleanup;
		}

		ret = semanage_copy_file(src, dst, sh->conf->file_mode,
					true);
		if (ret < 0) {
			ERR(sh, "Could not copy %s to %s.", src, dst);
			goto cleanup;
		}
	}

	if (!sh->do_reload)
		goto skip_reload;

	/* This stats what libselinux says the active store is (according to config)
	 * and what we are installing to, to decide if they are the same store. If
	 * they are not then we do not reload policy.
	 */
	const char *really_active_store = selinux_policy_root();
	struct stat astore;
	struct stat istore;
	const char *storepath = semanage_final_path(SEMANAGE_FINAL_SELINUX,
						    SEMANAGE_FINAL_TOPLEVEL);

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
	status = 0;
cleanup:
	return status;
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

	/* sync changes in sandbox to filesystem */
	fd = open(sandbox, O_DIRECTORY);
	if (fd == -1) {
		ERR(sh, "Error while opening %s for syncfs(): %d", sandbox, errno);
		return -1;
	}
	if (syncfs(fd) == -1) {
		ERR(sh, "Error while syncing %s to filesystem: %d", sandbox, errno);
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

	if (semanage_rename(sh, active, backup) == -1) {
		ERR(sh, "Error while renaming %s to %s.", active, backup);
		retval = -1;
		goto cleanup;
	}

	/* clean up some files from the sandbox before install */
	/* remove homedir_template from sandbox */

	if (semanage_rename(sh, sandbox, active) == -1) {
		ERR(sh, "Error while renaming %s to %s.", sandbox, active);
		/* note that if an error occurs during the next
		 * function then the store will be left in an
		 * inconsistent state */
		if (semanage_rename(sh, backup, active) < 0)
			ERR(sh, "Error while renaming %s back to %s.", backup,
			    active);
		retval = -1;
		goto cleanup;
	}
	if (semanage_install_final_tmp(sh) != 0) {
		/* note that if an error occurs during the next three
		 * function then the store will be left in an
		 * inconsistent state */
		int errsv = errno;
		if (semanage_rename(sh, active, sandbox) < 0)
			ERR(sh, "Error while renaming %s back to %s.", active,
			    sandbox);
		else if (semanage_rename(sh, backup, active) < 0)
			ERR(sh, "Error while renaming %s back to %s.", backup,
			    active);
		else
			semanage_install_final_tmp(sh);
		errno = errsv;
		retval = -1;
		goto cleanup;
	}

	if (!sh->conf->save_previous) {
		int errsv = errno;
		if (semanage_remove_directory(backup) != 0) {
			ERR(sh, "Could not delete previous directory %s.", backup);
			retval = -1;
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

	if (semanage_validate_and_compile_fcontexts(sh) < 0)
		goto cleanup;

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

int semanage_load_files(semanage_handle_t * sh, cil_db_t *cildb, char **filenames, int numfiles)
{
	int i, retval = 0;
	char *filename;
	struct file_contents contents = {};

	for (i = 0; i < numfiles; i++) {
		filename = filenames[i];

		retval = map_compressed_file(sh, filename, &contents);
		if (retval < 0)
			return -1;

		retval = cil_add_file(cildb, filename, contents.data, contents.len);
		unmap_compressed_file(&contents);

		if (retval != SEPOL_OK) {
			ERR(sh, "Error while reading from file %s.", filename);
			return -1;
		}
	}

	return 0;
}

/* 
 * Expands the policy contained within *base 
 */

/**
 * Read the policy from the sandbox (linked or kernel)
 */
int semanage_read_policydb(semanage_handle_t * sh, sepol_policydb_t * in,
			   enum semanage_sandbox_defs file)
{

	int retval = STATUS_ERR;
	const char *kernel_filename = NULL;
	struct sepol_policy_file *pf = NULL;
	FILE *infile = NULL;

	if ((kernel_filename =
	     semanage_path(SEMANAGE_ACTIVE, file)) == NULL) {
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
 * Writes the policy to the sandbox (linked or kernel)
 */
int semanage_write_policydb(semanage_handle_t * sh, sepol_policydb_t * out,
			    enum semanage_sandbox_defs file)
{

	int retval = STATUS_ERR;
	const char *kernel_filename = NULL;
	struct sepol_policy_file *pf = NULL;
	FILE *outfile = NULL;
	mode_t mask = umask(0077);

	if ((kernel_filename =
	     semanage_path(SEMANAGE_TMP, file)) == NULL) {
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
	umask(mask);
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
	    semanage_final_path(SEMANAGE_FINAL_TMP, SEMANAGE_KERNEL);
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
 * there is only one bucket (pointed to by "main") that
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
static void semanage_fc_merge_sort(semanage_file_context_bucket_t * main)
{
	semanage_file_context_bucket_t *current;
	semanage_file_context_bucket_t *temp;

	/* Loop until "main" is the only bucket left.
	 * When we stop "main" contains the sorted list. */
	while (main->next) {
		current = main;

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
	semanage_file_context_bucket_t *main;
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
	bcurrent = main = (semanage_file_context_bucket_t *)
	    calloc(1, sizeof(semanage_file_context_bucket_t));
	if (!main) {
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
				semanage_fc_bucket_list_destroy(main);
				return -1;
			}

			bcurrent = bcurrent->next;
		}
	}

	/* Sort the bucket list. */
	semanage_fc_merge_sort(main);

	/* First, calculate how much space we'll need for 
	 * the newly sorted block of data.  (We don't just
	 * use buf_len for this because we have extracted
	 * comments and whitespace.) */
	i = 0;
	current = main->data;
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
		semanage_fc_bucket_list_destroy(main);
		return -1;
	}
	*sorted_buf_len = i;

	/* Output the sorted semanage_file_context linked list to the char buffer. */
	sorted_buf_pos = *sorted_buf;
	current = main->data;
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
	semanage_fc_bucket_list_destroy(main);

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
