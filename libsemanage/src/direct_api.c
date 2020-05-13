/* Author: Jason Tang	  <jtang@tresys.com>
 *         Christopher Ashworth <cashworth@tresys.com>
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

#include <sepol/module.h>
#include <sepol/handle.h>
#include <sepol/cil/cil.h>
#include <selinux/selinux.h>

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <limits.h>
#include <errno.h>
#include <dirent.h>

#include "user_internal.h"
#include "seuser_internal.h"
#include "port_internal.h"
#include "ibpkey_internal.h"
#include "ibendport_internal.h"
#include "iface_internal.h"
#include "boolean_internal.h"
#include "fcontext_internal.h"
#include "node_internal.h"
#include "genhomedircon.h"

#include "debug.h"
#include "handle.h"
#include "modules.h"
#include "direct_api.h"
#include "semanage_store.h"
#include "database_policydb.h"
#include "policy.h"
#include <sys/mman.h>
#include <sys/wait.h>

#define PIPE_READ 0
#define PIPE_WRITE 1
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

static void semanage_direct_destroy(semanage_handle_t * sh);
static int semanage_direct_disconnect(semanage_handle_t * sh);
static int semanage_direct_begintrans(semanage_handle_t * sh);
static int semanage_direct_commit(semanage_handle_t * sh);
static int semanage_direct_install(semanage_handle_t * sh, char *data,
				   size_t data_len, const char *module_name, const char *lang_ext);
static int semanage_direct_install_file(semanage_handle_t * sh, const char *module_name);
static int semanage_direct_extract(semanage_handle_t * sh,
					   semanage_module_key_t *modkey,
					   int extract_cil,
					   void **mapped_data,
					   size_t *data_len,
					   semanage_module_info_t **modinfo);
static int semanage_direct_remove(semanage_handle_t * sh, char *module_name);
static int semanage_direct_list(semanage_handle_t * sh,
				semanage_module_info_t ** modinfo,
				int *num_modules);
static int semanage_direct_get_enabled(semanage_handle_t *sh,
				       const semanage_module_key_t *modkey,
				       int *enabled);
static int semanage_direct_set_enabled(semanage_handle_t *sh,
				       const semanage_module_key_t *modkey,
				       int enabled);

static int semanage_direct_get_module_info(semanage_handle_t *sh,
					   const semanage_module_key_t *modkey,
					   semanage_module_info_t **modinfo);

static int semanage_direct_list_all(semanage_handle_t *sh,
				    semanage_module_info_t **modinfo,
				    int *num_modules);

static int semanage_direct_install_info(semanage_handle_t *sh,
					const semanage_module_info_t *modinfo,
					char *data,
					size_t data_len);

static int semanage_direct_remove_key(semanage_handle_t *sh,
				      const semanage_module_key_t *modkey);

static struct semanage_policy_table direct_funcs = {
	.get_serial = semanage_direct_get_serial,
	.destroy = semanage_direct_destroy,
	.disconnect = semanage_direct_disconnect,
	.begin_trans = semanage_direct_begintrans,
	.commit = semanage_direct_commit,
	.install = semanage_direct_install,
	.extract = semanage_direct_extract,
	.install_file = semanage_direct_install_file,
	.remove = semanage_direct_remove,
	.list = semanage_direct_list,
	.get_enabled = semanage_direct_get_enabled,
	.set_enabled = semanage_direct_set_enabled,
	.get_module_info = semanage_direct_get_module_info,
	.list_all = semanage_direct_list_all,
	.install_info = semanage_direct_install_info,
	.remove_key = semanage_direct_remove_key,
};

int semanage_direct_is_managed(semanage_handle_t * sh)
{
	if (semanage_check_init(sh, sh->conf->store_root_path))
		goto err;

	if (semanage_access_check(sh) < 0)
		return 0;

	return 1;

      err:
	ERR(sh, "could not check whether policy is managed");
	return STATUS_ERR;
}

/* Check that the module store exists, creating it if necessary.
 */
int semanage_direct_connect(semanage_handle_t * sh)
{
	const char *path;
	struct stat sb;

	if (semanage_check_init(sh, sh->conf->store_root_path))
		goto err;

	if (sh->create_store)
		if (semanage_create_store(sh, 1))
			goto err;

	sh->u.direct.translock_file_fd = -1;
	sh->u.direct.activelock_file_fd = -1;

	/* set up function pointers */
	sh->funcs = &direct_funcs;

	/* Object databases: local modifications */
	if (user_base_file_dbase_init(sh,
				      semanage_path(SEMANAGE_ACTIVE,
						    SEMANAGE_USERS_BASE_LOCAL),
				      semanage_path(SEMANAGE_TMP,
						    SEMANAGE_USERS_BASE_LOCAL),
				      semanage_user_base_dbase_local(sh)) < 0)
		goto err;

	if (user_extra_file_dbase_init(sh,
				       semanage_path(SEMANAGE_ACTIVE,
						     SEMANAGE_USERS_EXTRA_LOCAL),
				       semanage_path(SEMANAGE_TMP,
						     SEMANAGE_USERS_EXTRA_LOCAL),
				       semanage_user_extra_dbase_local(sh)) < 0)
		goto err;

	if (user_join_dbase_init(sh,
				 semanage_user_base_dbase_local(sh),
				 semanage_user_extra_dbase_local(sh),
				 semanage_user_dbase_local(sh)) < 0)
		goto err;

	if (port_file_dbase_init(sh,
				 semanage_path(SEMANAGE_ACTIVE,
					       SEMANAGE_PORTS_LOCAL),
				 semanage_path(SEMANAGE_TMP,
					       SEMANAGE_PORTS_LOCAL),
				 semanage_port_dbase_local(sh)) < 0)
		goto err;

	if (iface_file_dbase_init(sh,
				  semanage_path(SEMANAGE_ACTIVE,
						SEMANAGE_INTERFACES_LOCAL),
				  semanage_path(SEMANAGE_TMP,
						SEMANAGE_INTERFACES_LOCAL),
				  semanage_iface_dbase_local(sh)) < 0)
		goto err;

	if (bool_file_dbase_init(sh,
				 semanage_path(SEMANAGE_ACTIVE,
					       SEMANAGE_BOOLEANS_LOCAL),
				 semanage_path(SEMANAGE_TMP,
					       SEMANAGE_BOOLEANS_LOCAL),
				 semanage_bool_dbase_local(sh)) < 0)
		goto err;

	if (fcontext_file_dbase_init(sh,
				     semanage_path(SEMANAGE_ACTIVE, SEMANAGE_STORE_FC_LOCAL),
				     semanage_path(SEMANAGE_TMP, SEMANAGE_STORE_FC_LOCAL),
				     semanage_fcontext_dbase_local(sh)) < 0)
		goto err;

	if (fcontext_file_dbase_init(sh,
				     semanage_path(SEMANAGE_ACTIVE, SEMANAGE_STORE_FC_HOMEDIRS),
				     semanage_path(SEMANAGE_TMP, SEMANAGE_STORE_FC_HOMEDIRS),
				     semanage_fcontext_dbase_homedirs(sh)) < 0)
		goto err;

	if (seuser_file_dbase_init(sh,
				   semanage_path(SEMANAGE_ACTIVE,
						 SEMANAGE_SEUSERS_LOCAL),
				   semanage_path(SEMANAGE_TMP,
						 SEMANAGE_SEUSERS_LOCAL),
				   semanage_seuser_dbase_local(sh)) < 0)
		goto err;

	if (node_file_dbase_init(sh,
				 semanage_path(SEMANAGE_ACTIVE,
					       SEMANAGE_NODES_LOCAL),
				 semanage_path(SEMANAGE_TMP,
					       SEMANAGE_NODES_LOCAL),
				 semanage_node_dbase_local(sh)) < 0)
		goto err;

	if (ibpkey_file_dbase_init(sh,
				   semanage_path(SEMANAGE_ACTIVE,
					         SEMANAGE_IBPKEYS_LOCAL),
				   semanage_path(SEMANAGE_TMP,
					         SEMANAGE_IBPKEYS_LOCAL),
				   semanage_ibpkey_dbase_local(sh)) < 0)
		goto err;

	if (ibendport_file_dbase_init(sh,
				      semanage_path(SEMANAGE_ACTIVE,
						    SEMANAGE_IBENDPORTS_LOCAL),
				      semanage_path(SEMANAGE_TMP,
						    SEMANAGE_IBENDPORTS_LOCAL),
				      semanage_ibendport_dbase_local(sh)) < 0)
		goto err;

	/* Object databases: local modifications + policy */
	if (user_base_policydb_dbase_init(sh,
					  semanage_user_base_dbase_policy(sh)) <
	    0)
		goto err;

	if (user_extra_file_dbase_init(sh,
				       semanage_path(SEMANAGE_ACTIVE,
						     SEMANAGE_USERS_EXTRA),
				       semanage_path(SEMANAGE_TMP,
						     SEMANAGE_USERS_EXTRA),
				       semanage_user_extra_dbase_policy(sh)) <
	    0)
		goto err;

	if (user_join_dbase_init(sh,
				 semanage_user_base_dbase_policy(sh),
				 semanage_user_extra_dbase_policy(sh),
				 semanage_user_dbase_policy(sh)) < 0)
		goto err;

	if (port_policydb_dbase_init(sh, semanage_port_dbase_policy(sh)) < 0)
		goto err;

	if (ibpkey_policydb_dbase_init(sh, semanage_ibpkey_dbase_policy(sh)) < 0)
		goto err;

	if (ibendport_policydb_dbase_init(sh, semanage_ibendport_dbase_policy(sh)) < 0)
		goto err;

	if (iface_policydb_dbase_init(sh, semanage_iface_dbase_policy(sh)) < 0)
		goto err;

	if (bool_policydb_dbase_init(sh, semanage_bool_dbase_policy(sh)) < 0)
		goto err;

	if (fcontext_file_dbase_init(sh,
				     semanage_path(SEMANAGE_ACTIVE, SEMANAGE_STORE_FC),
				     semanage_path(SEMANAGE_TMP, SEMANAGE_STORE_FC),
				     semanage_fcontext_dbase_policy(sh)) < 0)
		goto err;

	if (seuser_file_dbase_init(sh,
				   semanage_path(SEMANAGE_ACTIVE, SEMANAGE_STORE_SEUSERS),
				   semanage_path(SEMANAGE_TMP, SEMANAGE_STORE_SEUSERS),
				   semanage_seuser_dbase_policy(sh)) < 0)
		goto err;

	if (node_policydb_dbase_init(sh, semanage_node_dbase_policy(sh)) < 0)
		goto err;

	/* Active kernel policy */
	if (bool_activedb_dbase_init(sh, semanage_bool_dbase_active(sh)) < 0)
		goto err;

	/* set the disable dontaudit value */
	path = semanage_path(SEMANAGE_ACTIVE, SEMANAGE_DISABLE_DONTAUDIT);

	if (stat(path, &sb) == 0)
		sepol_set_disable_dontaudit(sh->sepolh, 1);
	else if (errno == ENOENT) {
		/* The file does not exist */
		sepol_set_disable_dontaudit(sh->sepolh, 0);
	} else {
		ERR(sh, "Unable to access %s: %s\n", path, strerror(errno));
		goto err;
	}

	return STATUS_SUCCESS;

      err:
	ERR(sh, "could not establish direct connection");
	return STATUS_ERR;
}

static void semanage_direct_destroy(semanage_handle_t * sh
					__attribute__ ((unused)))
{
	/* do nothing */
}

static int semanage_remove_tmps(semanage_handle_t *sh)
{
	if (sh->commit_err)
		return 0;

	/* destroy sandbox if it exists */
	if (semanage_remove_directory
	    (semanage_path(SEMANAGE_TMP, SEMANAGE_TOPLEVEL)) < 0) {
		if (errno != ENOENT) {
			ERR(sh, "Could not cleanly remove sandbox %s.",
			    semanage_path(SEMANAGE_TMP, SEMANAGE_TOPLEVEL));
			return -1;
		}
	}

	/* destroy tmp policy if it exists */
	if (semanage_remove_directory
	    (semanage_final_path(SEMANAGE_FINAL_TMP,
				 SEMANAGE_FINAL_TOPLEVEL)) < 0) {
		if (errno != ENOENT) {
			ERR(sh, "Could not cleanly remove tmp %s.",
			    semanage_final_path(SEMANAGE_FINAL_TMP,
						SEMANAGE_FINAL_TOPLEVEL));
			return -1;
		}
	}

	return 0;
}

static int semanage_direct_disconnect(semanage_handle_t *sh)
{
	int retval = 0;

	/* destroy transaction and remove tmp files if no commit error */
	if (sh->is_in_transaction) {
		retval = semanage_remove_tmps(sh);
		semanage_release_trans_lock(sh);
	}

	/* Release object databases: local modifications */
	user_base_file_dbase_release(semanage_user_base_dbase_local(sh));
	user_extra_file_dbase_release(semanage_user_extra_dbase_local(sh));
	user_join_dbase_release(semanage_user_dbase_local(sh));
	port_file_dbase_release(semanage_port_dbase_local(sh));
	ibpkey_file_dbase_release(semanage_ibpkey_dbase_local(sh));
	ibendport_file_dbase_release(semanage_ibendport_dbase_local(sh));
	iface_file_dbase_release(semanage_iface_dbase_local(sh));
	bool_file_dbase_release(semanage_bool_dbase_local(sh));
	fcontext_file_dbase_release(semanage_fcontext_dbase_local(sh));
	fcontext_file_dbase_release(semanage_fcontext_dbase_homedirs(sh));
	seuser_file_dbase_release(semanage_seuser_dbase_local(sh));
	node_file_dbase_release(semanage_node_dbase_local(sh));

	/* Release object databases: local modifications + policy */
	user_base_policydb_dbase_release(semanage_user_base_dbase_policy(sh));
	user_extra_file_dbase_release(semanage_user_extra_dbase_policy(sh));
	user_join_dbase_release(semanage_user_dbase_policy(sh));
	port_policydb_dbase_release(semanage_port_dbase_policy(sh));
	ibpkey_policydb_dbase_release(semanage_ibpkey_dbase_policy(sh));
	ibendport_policydb_dbase_release(semanage_ibendport_dbase_policy(sh));
	iface_policydb_dbase_release(semanage_iface_dbase_policy(sh));
	bool_policydb_dbase_release(semanage_bool_dbase_policy(sh));
	fcontext_file_dbase_release(semanage_fcontext_dbase_policy(sh));
	seuser_file_dbase_release(semanage_seuser_dbase_policy(sh));
	node_policydb_dbase_release(semanage_node_dbase_policy(sh));

	/* Release object databases: active kernel policy */
	bool_activedb_dbase_release(semanage_bool_dbase_active(sh));

	return retval;
}

static int semanage_direct_begintrans(semanage_handle_t * sh)
{
	if (semanage_get_trans_lock(sh) < 0) {
		return -1;
	}
	if ((semanage_make_sandbox(sh)) < 0) {
		return -1;
	}
	if ((semanage_make_final(sh)) < 0) {
		return -1;
	}
	return 0;
}

/********************* utility functions *********************/

/* Takes a module stored in 'module_data' and parses its headers.
 * Sets reference variables 'module_name' to module's name, and
 * 'version' to module's version.  The caller is responsible for
 * free()ing 'module_name', and 'version'; they will be
 * set to NULL upon entering this function.  Returns 0 on success, -1
 * if out of memory.
 */
static int parse_module_headers(semanage_handle_t * sh, char *module_data,
                               size_t data_len, char **module_name,
                               char **version)
{
       struct sepol_policy_file *pf;
       int file_type;
       *module_name = *version = NULL;

       if (sepol_policy_file_create(&pf)) {
               ERR(sh, "Out of memory!");
               return -1;
       }
       sepol_policy_file_set_mem(pf, module_data, data_len);
       sepol_policy_file_set_handle(pf, sh->sepolh);
       if (module_data != NULL && data_len > 0)
           sepol_module_package_info(pf, &file_type, module_name,
                                     version);
       sepol_policy_file_free(pf);

       return 0;
}

#include <stdlib.h>
#include <bzlib.h>
#include <string.h>
#include <sys/sendfile.h>

/* bzip() a data to a file, returning the total number of compressed bytes
 * in the file.  Returns -1 if file could not be compressed. */
static ssize_t bzip(semanage_handle_t *sh, const char *filename, char *data,
			size_t num_bytes)
{
	BZFILE* b;
	size_t  size = 1<<16;
	int     bzerror;
	size_t  total = 0;
	size_t len = 0;
	FILE *f;

	if ((f = fopen(filename, "wb")) == NULL) {
		return -1;
	}

	if (!sh->conf->bzip_blocksize) {
		if (fwrite(data, 1, num_bytes, f) < num_bytes) {
			fclose(f);
			return -1;
		}
		fclose(f);
		return num_bytes;
	}

	b = BZ2_bzWriteOpen( &bzerror, f, sh->conf->bzip_blocksize, 0, 0);
	if (bzerror != BZ_OK) {
		BZ2_bzWriteClose ( &bzerror, b, 1, 0, 0 );
		return -1;
	}
	
	while ( num_bytes > total ) {
		if (num_bytes - total > size) {
			len = size;
		} else {
			len = num_bytes - total;
		}
		BZ2_bzWrite ( &bzerror, b, &data[total], len );
		if (bzerror == BZ_IO_ERROR) { 
			BZ2_bzWriteClose ( &bzerror, b, 1, 0, 0 );
			return -1;
		}
		total += len;
	}

	BZ2_bzWriteClose ( &bzerror, b, 0, 0, 0 );
	fclose(f);
	if (bzerror == BZ_IO_ERROR) {
		return -1;
	}
	return total;
}

#define BZ2_MAGICSTR "BZh"
#define BZ2_MAGICLEN (sizeof(BZ2_MAGICSTR)-1)

/* bunzip() a file to '*data', returning the total number of uncompressed bytes
 * in the file.  Returns -1 if file could not be decompressed. */
ssize_t bunzip(semanage_handle_t *sh, FILE *f, char **data)
{
	BZFILE* b = NULL;
	size_t  nBuf;
	char*   buf = NULL;
	size_t  size = 1<<18;
	size_t  bufsize = size;
	int     bzerror;
	size_t  total = 0;
	char*   uncompress = NULL;
	char*   tmpalloc = NULL;
	int     ret = -1;

	buf = malloc(bufsize);
	if (buf == NULL) {
		ERR(sh, "Failure allocating memory.");
		goto exit;
	}

	/* Check if the file is bzipped */
	bzerror = fread(buf, 1, BZ2_MAGICLEN, f);
	rewind(f);
	if ((bzerror != BZ2_MAGICLEN) || memcmp(buf, BZ2_MAGICSTR, BZ2_MAGICLEN)) {
		goto exit;
	}

	b = BZ2_bzReadOpen ( &bzerror, f, 0, sh->conf->bzip_small, NULL, 0 );
	if ( bzerror != BZ_OK ) {
		ERR(sh, "Failure opening bz2 archive.");
		goto exit;
	}

	uncompress = malloc(size);
	if (uncompress == NULL) {
		ERR(sh, "Failure allocating memory.");
		goto exit;
	}

	while ( bzerror == BZ_OK) {
		nBuf = BZ2_bzRead ( &bzerror, b, buf, bufsize);
		if (( bzerror == BZ_OK ) || ( bzerror == BZ_STREAM_END )) {
			if (total + nBuf > size) {
				size *= 2;
				tmpalloc = realloc(uncompress, size);
				if (tmpalloc == NULL) {
					ERR(sh, "Failure allocating memory.");
					goto exit;
				}
				uncompress = tmpalloc;
			}
			memcpy(&uncompress[total], buf, nBuf);
			total += nBuf;
		}
	}
	if ( bzerror != BZ_STREAM_END ) {
		ERR(sh, "Failure reading bz2 archive.");
		goto exit;
	}

	ret = total;
	*data = uncompress;

exit:
	BZ2_bzReadClose ( &bzerror, b );
	free(buf);
	if ( ret < 0 ) {
		free(uncompress);
	}
	return ret;
}

/* mmap() a file to '*data',
 *  If the file is bzip compressed map_file will uncompress 
 * the file into '*data'.
 * Returns the total number of bytes in memory .
 * Returns -1 if file could not be opened or mapped. */
static ssize_t map_file(semanage_handle_t *sh, const char *path, char **data,
			int *compressed)
{
	ssize_t size = -1;
	char *uncompress;
	int fd = -1;
	FILE *file = NULL;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		ERR(sh, "Unable to open %s\n", path);
		return -1;
	}

	file = fdopen(fd, "r");
	if (file == NULL) {
		ERR(sh, "Unable to open %s\n", path);
		close(fd);
		return -1;
	}

	if ((size = bunzip(sh, file, &uncompress)) > 0) {
		*data = mmap(0, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
		if (*data == MAP_FAILED) {
			free(uncompress);
			fclose(file);
			return -1;
		} else {
			memcpy(*data, uncompress, size);
		}
		free(uncompress);
		*compressed = 1;
	} else {
		struct stat sb;
		if (fstat(fd, &sb) == -1 ||
		    (*data = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) ==
		    MAP_FAILED) {
			size = -1;
		} else {
			size = sb.st_size;
		}
		*compressed = 0;
	} 

	fclose(file);

	return size;
}

/* Writes a block of data to a file.  Returns 0 on success, -1 on
 * error. */
static int write_file(semanage_handle_t * sh,
		      const char *filename, char *data, size_t num_bytes)
{
	int out;

	if ((out =
	     open(filename, O_WRONLY | O_CREAT | O_TRUNC,
		  S_IRUSR | S_IWUSR)) == -1) {
		ERR(sh, "Could not open %s for writing.", filename);
		return -1;
	}
	if (write(out, data, num_bytes) == -1) {
		ERR(sh, "Error while writing to %s.", filename);
		close(out);
		return -1;
	}
	close(out);
	return 0;
}

static int semanage_direct_update_user_extra(semanage_handle_t * sh, cil_db_t *cildb)
{
	const char *ofilename = NULL;
	int retval = -1;
	char *data = NULL;
	size_t size = 0;

	dbase_config_t *pusers_extra = semanage_user_extra_dbase_policy(sh);

	retval = cil_userprefixes_to_string(cildb, &data, &size);
	if (retval != SEPOL_OK) {
		goto cleanup;
	}

	if (size > 0) {
		/*
		 * Write the users_extra entries from CIL modules.
		 * This file is used as our baseline when we do not require
		 * re-linking.
		 */
		ofilename = semanage_path(SEMANAGE_TMP,
					  SEMANAGE_USERS_EXTRA_LINKED);
		if (ofilename == NULL) {
			retval = -1;
			goto cleanup;
		}
		retval = write_file(sh, ofilename, data, size);
		if (retval < 0)
			goto cleanup;

		/*
		 * Write the users_extra file; users_extra.local
		 * will be merged into this file.
		 */
		ofilename = semanage_path(SEMANAGE_TMP, SEMANAGE_USERS_EXTRA);
		if (ofilename == NULL) {
			retval = -1;
			goto cleanup;
		}
		retval = write_file(sh, ofilename, data, size);
		if (retval < 0)
			goto cleanup;

		pusers_extra->dtable->drop_cache(pusers_extra->dbase);
		
	} else {
		retval =  pusers_extra->dtable->clear(sh, pusers_extra->dbase);
	}

cleanup:
	free(data);

	return retval;
}

static int semanage_direct_update_seuser(semanage_handle_t * sh, cil_db_t *cildb)
{
	const char *ofilename = NULL;
	int retval = -1;
	char *data = NULL;
	size_t size = 0;

	dbase_config_t *pseusers = semanage_seuser_dbase_policy(sh);

	retval = cil_selinuxusers_to_string(cildb, &data, &size);
	if (retval != SEPOL_OK) {
		goto cleanup;
	}

	if (size > 0) {
		/*
		 * Write the seusers entries from CIL modules.
		 * This file is used as our baseline when we do not require
		 * re-linking.
		 */
		ofilename = semanage_path(SEMANAGE_TMP,
					  SEMANAGE_SEUSERS_LINKED);
		if (ofilename == NULL) {
			retval = -1;
			goto cleanup;
		}
		retval = write_file(sh, ofilename, data, size);
		if (retval < 0)
			goto cleanup;

		/*
		 * Write the seusers file; seusers.local will be merged into
		 * this file.
		 */
		ofilename = semanage_path(SEMANAGE_TMP, SEMANAGE_STORE_SEUSERS);
		if (ofilename == NULL) {
			retval = -1;
			goto cleanup;
		}
		retval = write_file(sh, ofilename, data, size);
		if (retval < 0)
			goto cleanup;

		pseusers->dtable->drop_cache(pseusers->dbase);
	} else {
		retval = pseusers->dtable->clear(sh, pseusers->dbase);
	}

cleanup:
	free(data);

	return retval;
}

static int read_from_pipe_to_data(semanage_handle_t *sh, size_t initial_len, int fd, char **out_data_read, size_t *out_read_len)
{
	size_t max_len = initial_len;
	size_t read_len = 0;
	size_t data_read_len = 0;
	char *data_read = NULL;

	if (max_len <= 0) {
		max_len = 1;
	}
	data_read = malloc(max_len * sizeof(*data_read));
	if (data_read == NULL) {
		ERR(sh, "Failed to malloc, out of memory.\n");
		return -1;
	}

	while ((read_len = read(fd, data_read + data_read_len, max_len - data_read_len)) > 0) {
		data_read_len += read_len;
		if (data_read_len == max_len) {
			max_len *= 2;
			data_read = realloc(data_read, max_len);
			if (data_read == NULL) {
				ERR(sh, "Failed to realloc, out of memory.\n");
				return -1;
			}
		}
	}

	*out_read_len = data_read_len;
	*out_data_read = data_read;

	return 0;
}

static int semanage_pipe_data(semanage_handle_t *sh, char *path, char *in_data, size_t in_data_len, char **out_data, size_t *out_data_len, char **err_data, size_t *err_data_len)
{
	int input_fd[2] = {-1, -1};
	int output_fd[2] = {-1, -1};
	int err_fd[2] = {-1, -1};
	pid_t pid;
	char *data_read = NULL;
	char *err_data_read = NULL;
	int retval;
	int status = 0;
	size_t initial_len;
	size_t data_read_len = 0;
	size_t err_data_read_len = 0;
	struct sigaction old_signal;
	struct sigaction new_signal;
	new_signal.sa_handler = SIG_IGN;
	sigemptyset(&new_signal.sa_mask);
	new_signal.sa_flags = 0;
	/* This is needed in case the read end of input_fd is closed causing a SIGPIPE signal to be sent.
	 * If SIGPIPE is not caught, the signal will cause semanage to terminate immediately. The sigaction below
	 * creates a new_signal that ignores SIGPIPE allowing the write to exit cleanly.
	 *
	 * Another sigaction is called in cleanup to restore the original behavior when a SIGPIPE is received.
	 */
	sigaction(SIGPIPE, &new_signal, &old_signal);

	retval = pipe(input_fd);
	if (retval == -1) {
		ERR(sh, "Unable to create pipe for input pipe: %s\n", strerror(errno));
		goto cleanup;
	}
	retval = pipe(output_fd);
	if (retval == -1) {
		ERR(sh, "Unable to create pipe for output pipe: %s\n", strerror(errno));
		goto cleanup;
	}
	retval = pipe(err_fd);
	if (retval == -1) {
		ERR(sh, "Unable to create pipe for error pipe: %s\n", strerror(errno));
		goto cleanup;
	}

	pid = fork();
	if (pid == -1) {
		ERR(sh, "Unable to fork from parent: %s.", strerror(errno));
		retval = -1;
		goto cleanup;
	} else if (pid == 0) {
		retval = dup2(input_fd[PIPE_READ], STDIN_FILENO);
		if (retval == -1) {
			ERR(sh, "Unable to dup2 input pipe: %s\n", strerror(errno));
			goto cleanup;
		}
		retval = dup2(output_fd[PIPE_WRITE], STDOUT_FILENO);
		if (retval == -1) {
			ERR(sh, "Unable to dup2 output pipe: %s\n", strerror(errno));
			goto cleanup;
		}
		retval = dup2(err_fd[PIPE_WRITE], STDERR_FILENO);
		if (retval == -1) {
			ERR(sh, "Unable to dup2 error pipe: %s\n", strerror(errno));
			goto cleanup;
		}

		retval = close(input_fd[PIPE_WRITE]);
		if (retval == -1) {
			ERR(sh, "Unable to close input pipe: %s\n", strerror(errno));
			goto cleanup;
		}
		retval = close(output_fd[PIPE_READ]);
		if (retval == -1) {
			ERR(sh, "Unable to close output pipe: %s\n", strerror(errno));
			goto cleanup;
		}
		retval = close(err_fd[PIPE_READ]);
		if (retval == -1) {
			ERR(sh, "Unable to close error pipe: %s\n", strerror(errno));
			goto cleanup;
		}
		retval = execl(path, path, NULL);
		if (retval == -1) {
			ERR(sh, "Unable to execute %s : %s\n", path, strerror(errno));
			_exit(EXIT_FAILURE);
		}
	} else {
		retval = close(input_fd[PIPE_READ]);
		input_fd[PIPE_READ] = -1;
		if (retval == -1) {
			ERR(sh, "Unable to close read end of input pipe: %s\n", strerror(errno));
			goto cleanup;
		}

		retval = close(output_fd[PIPE_WRITE]);
		output_fd[PIPE_WRITE] = -1;
		if (retval == -1) {
			ERR(sh, "Unable to close write end of output pipe: %s\n", strerror(errno));
			goto cleanup;
		}

		retval = close(err_fd[PIPE_WRITE]);
		err_fd[PIPE_WRITE] = -1;
		if (retval == -1) {
			ERR(sh, "Unable to close write end of error pipe: %s\n", strerror(errno));
			goto cleanup;
		}

		retval = write(input_fd[PIPE_WRITE], in_data, in_data_len);
		if (retval == -1) {
			ERR(sh, "Failed to write data to input pipe: %s\n", strerror(errno));
			goto cleanup;
		}
		retval = close(input_fd[PIPE_WRITE]);
		input_fd[PIPE_WRITE] = -1;
		if (retval == -1) {
			ERR(sh, "Unable to close write end of input pipe: %s\n", strerror(errno));
			goto cleanup;
		}

		initial_len = 1 << 17;
		retval = read_from_pipe_to_data(sh, initial_len, output_fd[PIPE_READ], &data_read, &data_read_len);
		if (retval != 0) {
			goto cleanup;
		}
		retval = close(output_fd[PIPE_READ]);
		output_fd[PIPE_READ] = -1;
		if (retval == -1) {
			ERR(sh, "Unable to close read end of output pipe: %s\n", strerror(errno));
			goto cleanup;
		}

		initial_len = 1 << 9;
		retval = read_from_pipe_to_data(sh, initial_len, err_fd[PIPE_READ], &err_data_read, &err_data_read_len);
		if (retval != 0) {
			goto cleanup;
		}
		retval = close(err_fd[PIPE_READ]);
		err_fd[PIPE_READ] = -1;
		if (retval == -1) {
			ERR(sh, "Unable to close read end of error pipe: %s\n", strerror(errno));
			goto cleanup;
		}

		if (waitpid(pid, &status, 0) == -1 || !WIFEXITED(status)) {
			ERR(sh, "Child process %s did not exit cleanly.", path);
			retval = -1;
			goto cleanup;
		}
		if (WEXITSTATUS(status) != 0) {
			ERR(sh, "Child process %s failed with code: %d.", path, WEXITSTATUS(status));
			retval = -1;
			goto cleanup;
		}
	}

	retval = 0;

cleanup:
	sigaction(SIGPIPE, &old_signal, NULL);

	if (data_read != NULL) {
		*out_data = data_read;
		*out_data_len = data_read_len;
	}

	if (err_data_read != NULL) {
		*err_data = err_data_read;
		*err_data_len = err_data_read_len;
	}

	if (output_fd[PIPE_READ] != -1) {
		close(output_fd[PIPE_READ]);
	}
	if (output_fd[PIPE_WRITE] != -1) {
		close(output_fd[PIPE_WRITE]);
	}
	if (err_fd[PIPE_READ] != -1) {
		close(err_fd[PIPE_READ]);
	}
	if (err_fd[PIPE_WRITE] != -1) {
		close(err_fd[PIPE_WRITE]);
	}
	if (input_fd[PIPE_READ] != -1) {
		close(input_fd[PIPE_READ]);
	}
	if (input_fd[PIPE_WRITE] != -1) {
		close(input_fd[PIPE_WRITE]);
	}

	return retval;
}

static int semanage_direct_write_langext(semanage_handle_t *sh,
				const char *lang_ext,
				const semanage_module_info_t *modinfo)
{
	int ret = -1;
	char fn[PATH_MAX];
	FILE *fp = NULL;

	ret = semanage_module_get_path(sh,
			modinfo,
			SEMANAGE_MODULE_PATH_LANG_EXT,
			fn,
			sizeof(fn));
	if (ret != 0) {
		goto cleanup;
	}

	fp = fopen(fn, "w");
	if (fp == NULL) {
		ERR(sh, "Unable to open %s module ext file.", modinfo->name);
		ret = -1;
		goto cleanup;
	}

	if (fputs(lang_ext, fp) < 0) {
		ERR(sh, "Unable to write %s module ext file.", modinfo->name);
		ret = -1;
		goto cleanup;
	}

	if (fclose(fp) != 0) {
		ERR(sh, "Unable to close %s module ext file.", modinfo->name);
		ret = -1;
		goto cleanup;
	}

	fp = NULL;

	ret = 0;

cleanup:
	if (fp != NULL) fclose(fp);

	return ret;
}

static int semanage_compile_module(semanage_handle_t *sh,
				semanage_module_info_t *modinfo)
{
	char cil_path[PATH_MAX];
	char hll_path[PATH_MAX];
	char *compiler_path = NULL;
	char *cil_data = NULL;
	char *err_data = NULL;
	char *hll_data = NULL;
	char *start = NULL;
	char *end = NULL;
	ssize_t hll_data_len = 0;
	ssize_t bzip_status;
	int status = 0;
	int compressed;
	size_t cil_data_len = 0;
	size_t err_data_len = 0;

	if (!strcasecmp(modinfo->lang_ext, "cil")) {
		goto cleanup;
	}

	status = semanage_get_hll_compiler_path(sh, modinfo->lang_ext, &compiler_path);
	if (status != 0) {
		goto cleanup;
	}

	status = semanage_module_get_path(
			sh,
			modinfo,
			SEMANAGE_MODULE_PATH_CIL,
			cil_path,
			sizeof(cil_path));
	if (status != 0) {
		goto cleanup;
	}

	status = semanage_module_get_path(
			sh,
			modinfo,
			SEMANAGE_MODULE_PATH_HLL,
			hll_path,
			sizeof(hll_path));
	if (status != 0) {
		goto cleanup;
	}

	if ((hll_data_len = map_file(sh, hll_path, &hll_data, &compressed)) <= 0) {
		ERR(sh, "Unable to read file %s\n", hll_path);
		status = -1;
		goto cleanup;
	}

	status = semanage_pipe_data(sh, compiler_path, hll_data, (size_t)hll_data_len, &cil_data, &cil_data_len, &err_data, &err_data_len);
	if (err_data_len > 0) {
		for (start = end = err_data; end < err_data + err_data_len; end++) {
			if (*end == '\n') {
				fprintf(stderr, "%s: ", modinfo->name);
				fwrite(start, 1, end - start + 1, stderr);
				start = end + 1;
			}
		}

		if (end != start) {
			fprintf(stderr, "%s: ", modinfo->name);
			fwrite(start, 1, end - start, stderr);
			fprintf(stderr, "\n");
		}
	}
	if (status != 0) {
		goto cleanup;
	}

	bzip_status = bzip(sh, cil_path, cil_data, cil_data_len);
	if (bzip_status == -1) {
		ERR(sh, "Failed to bzip %s\n", cil_path);
		status = -1;
		goto cleanup;
	}

	if (sh->conf->remove_hll == 1) {
		status = unlink(hll_path);
		if (status != 0) {
			ERR(sh, "Error while removing HLL file %s: %s", hll_path, strerror(errno));
			goto cleanup;
		}

		status = semanage_direct_write_langext(sh, "cil", modinfo);
		if (status != 0) {
			goto cleanup;
		}
	}

cleanup:
	if (hll_data_len > 0) {
		munmap(hll_data, hll_data_len);
	}
	free(cil_data);
	free(err_data);
	free(compiler_path);

	return status;
}

static int semanage_compile_hll_modules(semanage_handle_t *sh,
				semanage_module_info_t *modinfos,
				int num_modinfos)
{
	int status = 0;
	int i;
	char cil_path[PATH_MAX];
	struct stat sb;

	assert(sh);
	assert(modinfos);

	for (i = 0; i < num_modinfos; i++) {
		status = semanage_module_get_path(
				sh,
				&modinfos[i],
				SEMANAGE_MODULE_PATH_CIL,
				cil_path,
				sizeof(cil_path));
		if (status != 0) {
			goto cleanup;
		}

		if (semanage_get_ignore_module_cache(sh) == 0 &&
				(status = stat(cil_path, &sb)) == 0) {
			continue;
		}
		if (status != 0 && errno != ENOENT) {
			ERR(sh, "Unable to access %s: %s\n", cil_path, strerror(errno));
			goto cleanup; //an error in the "stat" call
		}

		status = semanage_compile_module(sh, &modinfos[i]);
		if (status < 0) {
			goto cleanup;
		}
	}

	status = 0;

cleanup:
	return status;
}

/* Copies a file from src to dst. If dst already exists then
 * overwrite it. If source doesn't exist then return success.
 * Returns 0 on success, -1 on error. */
static int copy_file_if_exists(const char *src, const char *dst, mode_t mode){
	int rc = semanage_copy_file(src, dst, mode, false);
	return (rc < 0 && errno != ENOENT) ? rc : 0;
}

/********************* direct API functions ********************/

/* Commits all changes in sandbox to the actual kernel policy.
 * Returns commit number on success, -1 on error.
 */
static int semanage_direct_commit(semanage_handle_t * sh)
{
	char **mod_filenames = NULL;
	char *fc_buffer = NULL;
	size_t fc_buffer_len = 0;
	const char *ofilename = NULL;
	const char *path;
	int retval = -1, num_modinfos = 0, i;
	sepol_policydb_t *out = NULL;
	struct cil_db *cildb = NULL;
	semanage_module_info_t *modinfos = NULL;
	mode_t mask = umask(0077);
	struct stat sb;

	int do_rebuild, do_write_kernel, do_install;
	int fcontexts_modified, ports_modified, seusers_modified,
		disable_dontaudit, preserve_tunables, ibpkeys_modified,
		ibendports_modified;
	dbase_config_t *users = semanage_user_dbase_local(sh);
	dbase_config_t *users_base = semanage_user_base_dbase_local(sh);
	dbase_config_t *pusers_base = semanage_user_base_dbase_policy(sh);
	dbase_config_t *pusers_extra = semanage_user_extra_dbase_policy(sh);
	dbase_config_t *ports = semanage_port_dbase_local(sh);
	dbase_config_t *pports = semanage_port_dbase_policy(sh);
	dbase_config_t *ibpkeys = semanage_ibpkey_dbase_local(sh);
	dbase_config_t *pibpkeys = semanage_ibpkey_dbase_policy(sh);
	dbase_config_t *ibendports = semanage_ibendport_dbase_local(sh);
	dbase_config_t *pibendports = semanage_ibendport_dbase_policy(sh);
	dbase_config_t *bools = semanage_bool_dbase_local(sh);
	dbase_config_t *pbools = semanage_bool_dbase_policy(sh);
	dbase_config_t *ifaces = semanage_iface_dbase_local(sh);
	dbase_config_t *pifaces = semanage_iface_dbase_policy(sh);
	dbase_config_t *nodes = semanage_node_dbase_local(sh);
	dbase_config_t *pnodes = semanage_node_dbase_policy(sh);
	dbase_config_t *fcontexts = semanage_fcontext_dbase_local(sh);
	dbase_config_t *pfcontexts = semanage_fcontext_dbase_policy(sh);
	dbase_config_t *seusers = semanage_seuser_dbase_local(sh);
	dbase_config_t *pseusers = semanage_seuser_dbase_policy(sh);

	/* Modified flags that we need to use more than once. */
	ports_modified = ports->dtable->is_modified(ports->dbase);
	ibpkeys_modified = ibpkeys->dtable->is_modified(ibpkeys->dbase);
	ibendports_modified = ibendports->dtable->is_modified(ibendports->dbase);
	seusers_modified = seusers->dtable->is_modified(seusers->dbase);
	fcontexts_modified = fcontexts->dtable->is_modified(fcontexts->dbase);

	/* Rebuild if explicitly requested or any module changes occurred. */
	do_rebuild = sh->do_rebuild | sh->modules_modified;

	/* Create or remove the disable_dontaudit flag file. */
	path = semanage_path(SEMANAGE_TMP, SEMANAGE_DISABLE_DONTAUDIT);
	if (stat(path, &sb) == 0)
		do_rebuild |= !(sepol_get_disable_dontaudit(sh->sepolh) == 1);
	else if (errno == ENOENT) {
		/* The file does not exist */
		do_rebuild |= (sepol_get_disable_dontaudit(sh->sepolh) == 1);
	} else {
		ERR(sh, "Unable to access %s: %s\n", path, strerror(errno));
		retval = -1;
		goto cleanup;
	}
	if (sepol_get_disable_dontaudit(sh->sepolh) == 1) {
		FILE *touch;
		touch = fopen(path, "w");
		if (touch != NULL) {
			if (fclose(touch) != 0) {
				ERR(sh, "Error attempting to create disable_dontaudit flag.");
				goto cleanup;
			}
		} else {
			ERR(sh, "Error attempting to create disable_dontaudit flag.");
			goto cleanup;
		}
	} else {
		if (remove(path) == -1 && errno != ENOENT) {
			ERR(sh, "Error removing the disable_dontaudit flag.");
			goto cleanup;
		}
	}

	/* Create or remove the preserve_tunables flag file. */
	path = semanage_path(SEMANAGE_TMP, SEMANAGE_PRESERVE_TUNABLES);
	if (stat(path, &sb) == 0)
		do_rebuild |= !(sepol_get_preserve_tunables(sh->sepolh) == 1);
	else if (errno == ENOENT) {
		/* The file does not exist */
		do_rebuild |= (sepol_get_preserve_tunables(sh->sepolh) == 1);
	} else {
		ERR(sh, "Unable to access %s: %s\n", path, strerror(errno));
		retval = -1;
		goto cleanup;
	}

	if (sepol_get_preserve_tunables(sh->sepolh) == 1) {
		FILE *touch;
		touch = fopen(path, "w");
		if (touch != NULL) {
			if (fclose(touch) != 0) {
				ERR(sh, "Error attempting to create preserve_tunable flag.");
				goto cleanup;
			}
		} else {
			ERR(sh, "Error attempting to create preserve_tunable flag.");
			goto cleanup;
		}
	} else {
		if (remove(path) == -1 && errno != ENOENT) {
			ERR(sh, "Error removing the preserve_tunables flag.");
			goto cleanup;
		}
	}

	/* Before we do anything else, flush the join to its component parts.
	 * This *does not* flush to disk automatically */
	if (users->dtable->is_modified(users->dbase)) {
		retval = users->dtable->flush(sh, users->dbase);
		if (retval < 0)
			goto cleanup;
	}

	/*
	 * This is for systems that have already migrated with an older version
	 * of semanage_migrate_store. The older version did not copy
	 * policy.kern so the policy binary must be rebuilt here.
	 * This also ensures that any linked files that are required
	 * in order to skip re-linking are present; otherwise, we force
	 * a rebuild.
	 */
	if (!do_rebuild) {
		int files[] = {SEMANAGE_STORE_KERNEL,
					   SEMANAGE_STORE_FC,
					   SEMANAGE_STORE_SEUSERS,
					   SEMANAGE_LINKED,
					   SEMANAGE_SEUSERS_LINKED,
					   SEMANAGE_USERS_EXTRA_LINKED};

		for (i = 0; i < (int) ARRAY_SIZE(files); i++) {
			path = semanage_path(SEMANAGE_TMP, files[i]);
			if (stat(path, &sb) != 0) {
				if (errno != ENOENT) {
					ERR(sh, "Unable to access %s: %s\n", path, strerror(errno));
					retval = -1;
					goto cleanup;
				}

				do_rebuild = 1;
				goto rebuild;
			}
		}
	}

rebuild:
	/*
	 * Now that we know whether or not a rebuild is required,
	 * we can determine what else needs to be done.
	 * We need to write the kernel policy if we are rebuilding
	 * or if any other policy component that lives in the kernel
	 * policy has been modified.
	 * We need to install the policy files if any of the managed files
	 * that live under /etc/selinux (kernel policy, seusers, file contexts)
	 * will be modified.
	 */
	do_write_kernel = do_rebuild | ports_modified | ibpkeys_modified |
		ibendports_modified |
		bools->dtable->is_modified(bools->dbase) |
		ifaces->dtable->is_modified(ifaces->dbase) |
		nodes->dtable->is_modified(nodes->dbase) |
		users->dtable->is_modified(users_base->dbase);
	do_install = do_write_kernel | seusers_modified | fcontexts_modified;

	/*
	 * If there were policy changes, or explicitly requested, or
	 * any required files are missing, rebuild the policy.
	 */
	if (do_rebuild) {
		/* =================== Module expansion =============== */

		retval = semanage_get_active_modules(sh, &modinfos, &num_modinfos);
		if (retval < 0) {
			goto cleanup;
		}

		if (num_modinfos == 0) {
			goto cleanup;
		}

		retval = semanage_compile_hll_modules(sh, modinfos, num_modinfos);
		if (retval < 0) {
			ERR(sh, "Failed to compile hll files into cil files.\n");
			goto cleanup;
		}

		retval = semanage_get_cil_paths(sh, modinfos, num_modinfos, &mod_filenames);
		if (retval < 0)
			goto cleanup;

		retval = semanage_verify_modules(sh, mod_filenames, num_modinfos);
		if (retval < 0)
			goto cleanup;

		cil_db_init(&cildb);

		disable_dontaudit = sepol_get_disable_dontaudit(sh->sepolh);
		preserve_tunables = sepol_get_preserve_tunables(sh->sepolh);
		cil_set_disable_dontaudit(cildb, disable_dontaudit);
		cil_set_disable_neverallow(cildb, !(sh->conf->expand_check));
		cil_set_preserve_tunables(cildb, preserve_tunables);
		cil_set_target_platform(cildb, sh->conf->target_platform);
		cil_set_policy_version(cildb, sh->conf->policyvers);

		if (sh->conf->handle_unknown != -1) {
			cil_set_handle_unknown(cildb, sh->conf->handle_unknown);
		}

		retval = semanage_load_files(sh, cildb, mod_filenames, num_modinfos);
		if (retval < 0) {
			goto cleanup;
		}

		retval = cil_compile(cildb);
		if (retval < 0)
			goto cleanup;

		retval = cil_build_policydb(cildb, &out);
		if (retval < 0)
			goto cleanup;

		/* File Contexts */
		retval = cil_filecons_to_string(cildb, &fc_buffer, &fc_buffer_len);
		if (retval < 0)
			goto cleanup;

		/* Write the contexts (including template contexts) to a single file. */
		ofilename = semanage_path(SEMANAGE_TMP, SEMANAGE_FC_TMPL);
		if (ofilename == NULL) {
			retval = -1;
			goto cleanup;
		}
		retval = write_file(sh, ofilename, fc_buffer, fc_buffer_len);
		if (retval < 0)
			goto cleanup;

		/* Split complete and template file contexts into their separate files. */
		retval = semanage_split_fc(sh);
		if (retval < 0)
			goto cleanup;

		/* remove FC_TMPL now that it is now longer needed */
		unlink(semanage_path(SEMANAGE_TMP, SEMANAGE_FC_TMPL));

		pfcontexts->dtable->drop_cache(pfcontexts->dbase);

		/* SEUsers */
		retval = semanage_direct_update_seuser(sh, cildb);
		if (retval < 0)
			goto cleanup;

		/* User Extra */
		retval = semanage_direct_update_user_extra(sh, cildb);
		if (retval < 0)
			goto cleanup;

		cil_db_destroy(&cildb);

		/* Remove redundancies in binary policy if requested. */
		if (sh->conf->optimize_policy) {
			retval = sepol_policydb_optimize(out);
			if (retval < 0)
				goto cleanup;
		}

		/* Write the linked policy before merging local changes. */
		retval = semanage_write_policydb(sh, out,
						 SEMANAGE_LINKED);
		if (retval < 0)
			goto cleanup;
	} else {
		/* Load the existing linked policy, w/o local changes */
		retval = sepol_policydb_create(&out);
		if (retval < 0)
			goto cleanup;

		retval = semanage_read_policydb(sh, out, SEMANAGE_LINKED);
		if (retval < 0)
			goto cleanup;

		path = semanage_path(SEMANAGE_TMP, SEMANAGE_SEUSERS_LINKED);
		if (stat(path, &sb) == 0) {
			retval = semanage_copy_file(path,
						    semanage_path(SEMANAGE_TMP,
								  SEMANAGE_STORE_SEUSERS),
						    0, false);
			if (retval < 0)
				goto cleanup;
			pseusers->dtable->drop_cache(pseusers->dbase);
		} else if (errno == ENOENT) {
			/* The file does not exist */
			pseusers->dtable->clear(sh, pseusers->dbase);
		} else {
			ERR(sh, "Unable to access %s: %s\n", path, strerror(errno));
			retval = -1;
			goto cleanup;
		}

		path = semanage_path(SEMANAGE_TMP, SEMANAGE_USERS_EXTRA_LINKED);
		if (stat(path, &sb) == 0) {
			retval = semanage_copy_file(path,
						    semanage_path(SEMANAGE_TMP,
								  SEMANAGE_USERS_EXTRA),
						    0, false);
			if (retval < 0)
				goto cleanup;
			pusers_extra->dtable->drop_cache(pusers_extra->dbase);
		} else if (errno == ENOENT) {
			/* The file does not exist */
			pusers_extra->dtable->clear(sh, pusers_extra->dbase);
		} else {
			ERR(sh, "Unable to access %s: %s\n", path, strerror(errno));
			retval = -1;
			goto cleanup;
		}
	}

	/* Attach our databases to the policydb we just created or loaded. */
	dbase_policydb_attach((dbase_policydb_t *) pusers_base->dbase, out);
	dbase_policydb_attach((dbase_policydb_t *) pports->dbase, out);
	dbase_policydb_attach((dbase_policydb_t *) pibpkeys->dbase, out);
	dbase_policydb_attach((dbase_policydb_t *) pibendports->dbase, out);
	dbase_policydb_attach((dbase_policydb_t *) pifaces->dbase, out);
	dbase_policydb_attach((dbase_policydb_t *) pbools->dbase, out);
	dbase_policydb_attach((dbase_policydb_t *) pnodes->dbase, out);

	/* Merge local changes */
	retval = semanage_base_merge_components(sh);
	if (retval < 0)
		goto cleanup;

	if (do_write_kernel) {
		/* Write new kernel policy. */
		retval = semanage_write_policydb(sh, out,
						 SEMANAGE_STORE_KERNEL);
		if (retval < 0)
			goto cleanup;

		/* Run the kernel policy verifier, if any. */
		retval = semanage_verify_kernel(sh);
		if (retval < 0)
			goto cleanup;
	}

	/* ======= Post-process: Validate non-policydb components ===== */

	/* Validate local modifications to file contexts.
	 * Note: those are still cached, even though they've been 
	 * merged into the main file_contexts. We won't check the 
	 * large file_contexts - checked at compile time */
	if (do_rebuild || fcontexts_modified) {
		retval = semanage_fcontext_validate_local(sh, out);
		if (retval < 0)
			goto cleanup;
	}

	/* Validate local seusers against policy */
	if (do_rebuild || seusers_modified) {
		retval = semanage_seuser_validate_local(sh, out);
		if (retval < 0)
			goto cleanup;
	}

	/* Validate local ports for overlap */
	if (do_rebuild || ports_modified) {
		retval = semanage_port_validate_local(sh);
		if (retval < 0)
			goto cleanup;
	}

	/* Validate local ibpkeys for overlap */
	if (do_rebuild || ibpkeys_modified) {
		retval = semanage_ibpkey_validate_local(sh);
		if (retval < 0)
			goto cleanup;
	}

	/* Validate local ibendports */
	if (do_rebuild || ibendports_modified) {
		retval = semanage_ibendport_validate_local(sh);
		if (retval < 0)
			goto cleanup;
	}
	/* ================== Write non-policydb components ========= */

	/* Commit changes to components */
	retval = semanage_commit_components(sh);
	if (retval < 0)
		goto cleanup;

	retval = semanage_copy_file(semanage_path(SEMANAGE_TMP, SEMANAGE_STORE_KERNEL),
			semanage_final_path(SEMANAGE_FINAL_TMP, SEMANAGE_KERNEL),
			sh->conf->file_mode, false);
	if (retval < 0) {
		goto cleanup;
	}

	retval = copy_file_if_exists(semanage_path(SEMANAGE_TMP, SEMANAGE_STORE_FC_LOCAL),
						semanage_final_path(SEMANAGE_FINAL_TMP, SEMANAGE_FC_LOCAL),
						sh->conf->file_mode);
	if (retval < 0) {
		goto cleanup;
	}

	retval = copy_file_if_exists(semanage_path(SEMANAGE_TMP, SEMANAGE_STORE_FC),
						semanage_final_path(SEMANAGE_FINAL_TMP, SEMANAGE_FC),
						sh->conf->file_mode);
	if (retval < 0) {
		goto cleanup;
	}

	retval = copy_file_if_exists(semanage_path(SEMANAGE_TMP, SEMANAGE_STORE_SEUSERS),
						semanage_final_path(SEMANAGE_FINAL_TMP, SEMANAGE_SEUSERS),
						sh->conf->file_mode);
	if (retval < 0) {
		goto cleanup;
	}

	/* run genhomedircon if its enabled, this should be the last operation
	 * which requires the out policydb */
	if (!sh->conf->disable_genhomedircon) {
		if (out){
			if ((retval = semanage_genhomedircon(sh, out, sh->conf->usepasswd,
								sh->conf->ignoredirs)) != 0) {
				ERR(sh, "semanage_genhomedircon returned error code %d.", retval);
				goto cleanup;
			}
			/* file_contexts.homedirs was created in SEMANAGE_TMP store */
			retval = semanage_copy_file(
						semanage_path(SEMANAGE_TMP, SEMANAGE_STORE_FC_HOMEDIRS),
						semanage_final_path(SEMANAGE_FINAL_TMP,	SEMANAGE_FC_HOMEDIRS),
						sh->conf->file_mode, false);
			if (retval < 0) {
				goto cleanup;
			}
		}
	} else {
		WARN(sh, "WARNING: genhomedircon is disabled. \
                               See /etc/selinux/semanage.conf if you need to enable it.");
        }

	/* free out, if we don't free it before calling semanage_install_sandbox 
	 * then fork() may fail on low memory machines */
	sepol_policydb_free(out);
	out = NULL;

	if (do_install)
		retval = semanage_install_sandbox(sh);

cleanup:
	for (i = 0; i < num_modinfos; i++) {
		semanage_module_info_destroy(sh, &modinfos[i]);
	}
	free(modinfos);

	for (i = 0; mod_filenames != NULL && i < num_modinfos; i++) {
		free(mod_filenames[i]);
	}

	/* Detach from policydb, so it can be freed */
	dbase_policydb_detach((dbase_policydb_t *) pusers_base->dbase);
	dbase_policydb_detach((dbase_policydb_t *) pports->dbase);
	dbase_policydb_detach((dbase_policydb_t *) pibpkeys->dbase);
	dbase_policydb_detach((dbase_policydb_t *) pibendports->dbase);
	dbase_policydb_detach((dbase_policydb_t *) pifaces->dbase);
	dbase_policydb_detach((dbase_policydb_t *) pnodes->dbase);
	dbase_policydb_detach((dbase_policydb_t *) pbools->dbase);

	free(mod_filenames);
	sepol_policydb_free(out);
	cil_db_destroy(&cildb);

	free(fc_buffer);

	/* Set commit_err so other functions can detect any errors. Note that
	 * retval > 0 will be the commit number.
	 */
	if (retval < 0)
		sh->commit_err = retval;

	if (semanage_remove_tmps(sh) != 0)
		retval = -1;

	semanage_release_trans_lock(sh);
	umask(mask);

	return retval;
}

/* Writes a module to the sandbox's module directory, overwriting any
 * previous module stored within.  Note that module data are not
 * free()d by this function; caller is responsible for deallocating it
 * if necessary.  Returns 0 on success, -1 if out of memory, -2 if the
 * data does not represent a valid module file, -3 if error while
 * writing file. */
static int semanage_direct_install(semanage_handle_t * sh,
				   char *data, size_t data_len,
				   const char *module_name, const char *lang_ext)
{
	int status = 0;
	int ret = 0;

	semanage_module_info_t modinfo;
	ret = semanage_module_info_init(sh, &modinfo);
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

	ret = semanage_module_info_set_priority(sh, &modinfo, sh->priority);
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

	ret = semanage_module_info_set_name(sh, &modinfo, module_name);
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

	ret = semanage_module_info_set_lang_ext(sh, &modinfo, lang_ext);
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

	ret = semanage_module_info_set_enabled(sh, &modinfo, -1);
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

	status = semanage_direct_install_info(sh, &modinfo, data, data_len);

cleanup:

	semanage_module_info_destroy(sh, &modinfo);

	return status;
}

/* Attempts to link a module to the sandbox's module directory, unlinking any
 * previous module stored within.  Returns 0 on success, -1 if out of memory, -2 if the
 * data does not represent a valid module file, -3 if error while
 * writing file. */

static int semanage_direct_install_file(semanage_handle_t * sh,
					const char *install_filename)
{

	int retval = -1;
	char *data = NULL;
	ssize_t data_len = 0;
	int compressed = 0;
	char *path = NULL;
	char *filename;
	char *lang_ext = NULL;
	char *module_name = NULL;
	char *separator;
	char *version = NULL;

	if ((data_len = map_file(sh, install_filename, &data, &compressed)) <= 0) {
		ERR(sh, "Unable to read file %s\n", install_filename);
		retval = -1;
		goto cleanup;
	}

	path = strdup(install_filename);
	if (path == NULL) {
		ERR(sh, "No memory available for strdup.\n");
		retval = -1;
		goto cleanup;
	}

	filename = basename(path);

	if (compressed) {
		separator = strrchr(filename, '.');
		if (separator == NULL) {
			ERR(sh, "Compressed module does not have a valid extension.");
			retval = -1;
			goto cleanup;
		}
		*separator = '\0';
		lang_ext = separator + 1;
	}

	separator = strrchr(filename, '.');
	if (separator == NULL) {
		if (lang_ext == NULL) {
			ERR(sh, "Module does not have a valid extension.");
			retval = -1;
			goto cleanup;
		}
	} else {
		*separator = '\0';
		lang_ext = separator + 1;
	}

	if (strcmp(lang_ext, "pp") == 0) {
		retval = parse_module_headers(sh, data, data_len, &module_name, &version);
		free(version);
		if (retval != 0)
			goto cleanup;
	}

	if (module_name == NULL) {
		module_name = strdup(filename);
		if (module_name == NULL) {
			ERR(sh, "No memory available for module_name.\n");
			retval = -1;
			goto cleanup;
		}
	} else if (strcmp(module_name, filename) != 0) {
		fprintf(stderr, "Warning: SELinux userspace will refer to the module from %s as %s rather than %s\n", install_filename, module_name, filename);
	}

	retval = semanage_direct_install(sh, data, data_len, module_name, lang_ext);

cleanup:
	if (data_len > 0) munmap(data, data_len);
	free(module_name);
	free(path);

	return retval;
}

static int semanage_direct_extract(semanage_handle_t * sh,
				   semanage_module_key_t *modkey,
				   int extract_cil,
				   void **mapped_data,
				   size_t *data_len,
				   semanage_module_info_t **modinfo)
{
	char module_path[PATH_MAX];
	char input_file[PATH_MAX];
	enum semanage_module_path_type file_type;
	int rc = -1;
	semanage_module_info_t *_modinfo = NULL;
	ssize_t _data_len;
	char *_data;
	int compressed;
	struct stat sb;

	/* get path of module */
	rc = semanage_module_get_path(
			sh,
			(const semanage_module_info_t *)modkey,
			SEMANAGE_MODULE_PATH_NAME,
			module_path,
			sizeof(module_path));
	if (rc != 0) {
		goto cleanup;
	}

	if (stat(module_path, &sb) != 0) {
		ERR(sh, "Unable to access %s: %s\n", module_path, strerror(errno));
		rc = -1;
		goto cleanup;
	}

	rc = semanage_module_get_module_info(sh,
			modkey,
			&_modinfo);
	if (rc != 0) {
		goto cleanup;
	}

	if (extract_cil || strcmp(_modinfo->lang_ext, "cil") == 0) {
		file_type = SEMANAGE_MODULE_PATH_CIL;
	} else {
		file_type = SEMANAGE_MODULE_PATH_HLL;
	}

	/* get path of what to extract */
	rc = semanage_module_get_path(
			sh,
			_modinfo,
			file_type,
			input_file,
			sizeof(input_file));
	if (rc != 0) {
		goto cleanup;
	}

	if (extract_cil == 1 && strcmp(_modinfo->lang_ext, "cil") && stat(input_file, &sb) != 0) {
		if (errno != ENOENT) {
			ERR(sh, "Unable to access %s: %s\n", input_file, strerror(errno));
			rc = -1;
			goto cleanup;
		}

		rc = semanage_compile_module(sh, _modinfo);
		if (rc < 0) {
			goto cleanup;
		}
	}

	_data_len = map_file(sh, input_file, &_data, &compressed);
	if (_data_len <= 0) {
		ERR(sh, "Error mapping file: %s", input_file);
		rc = -1;
		goto cleanup;
	}

	*modinfo = _modinfo;
	*data_len = (size_t)_data_len;
	*mapped_data = _data;

cleanup:
	if (rc != 0) {
		semanage_module_info_destroy(sh, _modinfo);
		free(_modinfo);
	}

	return rc;
}

/* Removes a module from the sandbox.  Returns 0 on success, -1 if out
 * of memory, -2 if module not found or could not be removed. */
static int semanage_direct_remove(semanage_handle_t * sh, char *module_name)
{
	int status = 0;
	int ret = 0;

	semanage_module_key_t modkey;
	ret = semanage_module_key_init(sh, &modkey);
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

	ret = semanage_module_key_set_priority(sh, &modkey, sh->priority);
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

	ret = semanage_module_key_set_name(sh, &modkey, module_name);
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

	status = semanage_direct_remove_key(sh, &modkey);

cleanup:
	return status;
}

/* Allocate an array of module_info structures for each readable
 * module within the store.  Note that if the calling program has
 * already begun a transaction then this function will get a list of
 * modules within the sandbox.	The caller is responsible for calling
 * semanage_module_info_datum_destroy() on each element of the array
 * as well as free()ing the entire list.
 */
static int semanage_direct_list(semanage_handle_t * sh,
				semanage_module_info_t ** modinfo,
				int *num_modules)
{
	int i, retval = -1;
	*modinfo = NULL;
	*num_modules = 0;

	/* get the read lock when reading from the active
	   (non-transaction) directory */
	if (!sh->is_in_transaction)
		if (semanage_get_active_lock(sh) < 0)
			return -1;

	if (semanage_get_active_modules(sh, modinfo, num_modules) == -1) {
		goto cleanup;
	}

	if (num_modules == 0) {
		retval = semanage_direct_get_serial(sh);
		goto cleanup;
	}

	retval = semanage_direct_get_serial(sh);

      cleanup:
	if (retval < 0) {
		for (i = 0; i < *num_modules; i++) {
			semanage_module_info_destroy(sh, &(*modinfo[i]));
			modinfo[i] = NULL;
		}
		free(*modinfo);
		*modinfo = NULL;
	}

	if (!sh->is_in_transaction) {
		semanage_release_active_lock(sh);
	}
	return retval;
}

static int semanage_direct_get_enabled(semanage_handle_t *sh,
				       const semanage_module_key_t *modkey,
				       int *enabled)
{
	assert(sh);
	assert(modkey);
	assert(enabled);

	int status = 0;
	int ret = 0;

	char path[PATH_MAX];
	struct stat sb;
	semanage_module_info_t *modinfo = NULL;

	/* get module info */
	ret = semanage_module_get_module_info(
			sh,
			modkey,
			&modinfo);
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

	/* get disabled file path */
	ret = semanage_module_get_path(
			sh,
			modinfo,
			SEMANAGE_MODULE_PATH_DISABLED,
			path,
			sizeof(path));
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

	if (stat(path, &sb) < 0) {
		if (errno != ENOENT) {
			ERR(sh, "Unable to access %s: %s\n", path, strerror(errno));
			status = -1;
			goto cleanup;
		}

		*enabled = 1;
	}
	else {
		*enabled = 0;
	}

cleanup:
	semanage_module_info_destroy(sh, modinfo);
	free(modinfo);

	return status;
}

static int semanage_direct_set_enabled(semanage_handle_t *sh,
				       const semanage_module_key_t *modkey,
				       int enabled)
{
	assert(sh);
	assert(modkey);

	int status = 0;
	int ret = 0;

	char fn[PATH_MAX];
	const char *path = NULL;
	FILE *fp = NULL;
	semanage_module_info_t *modinfo = NULL;
	mode_t mask;

	/* check transaction */
	if (!sh->is_in_transaction) {
		if (semanage_begin_transaction(sh) < 0) {
			status = -1;
			goto cleanup;
		}
	}

	/* validate name */
	ret = semanage_module_validate_name(modkey->name);
	if (ret != 0) {
		errno = 0;
		ERR(sh, "Name %s is invalid.", modkey->name);
		status = -1;
		goto cleanup;
	}

	/* validate enabled */
	ret = semanage_module_validate_enabled(enabled);
	if (ret != 0) {
		errno = 0;
		ERR(sh, "Enabled status %d is invalid.", enabled);
		status = -1;
		goto cleanup;
	}

	/* check for disabled path, create if missing */
	path = semanage_path(SEMANAGE_TMP, SEMANAGE_MODULES_DISABLED);

	ret = semanage_mkdir(sh, path);
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

	/* get module info */
	ret = semanage_module_get_module_info(
			sh,
			modkey,
			&modinfo);
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

	/* get module disabled file */
	ret = semanage_module_get_path(
			sh,
			modinfo,
			SEMANAGE_MODULE_PATH_DISABLED,
			fn,
			sizeof(fn));
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

	switch (enabled) {
		case 0: /* disable the module */
			mask = umask(0077);
			fp = fopen(fn, "w");
			umask(mask);

			if (fp == NULL) {
				ERR(sh,
				    "Unable to disable module %s",
				    modkey->name);
				status = -1;
				goto cleanup;
			}

			if (fclose(fp) != 0) {
				ERR(sh,
				    "Unable to close disabled file for module %s",
				    modkey->name);
				status = -1;
				goto cleanup;
			}

			fp = NULL;

			break;
		case 1: /* enable the module */
			if (unlink(fn) < 0) {
				if (errno != ENOENT) {
					ERR(sh,
					    "Unable to enable module %s",
					    modkey->name);
					status = -1;
					goto cleanup;
				}
				else {
					/* module already enabled */
					errno = 0;
				}
			}

			break;
		case -1: /* warn about ignored setting to default */
			WARN(sh,
			     "Setting module %s to 'default' state has no effect",
			     modkey->name);
			break;
	}

cleanup:
	semanage_module_info_destroy(sh, modinfo);
	free(modinfo);

	if (fp != NULL) fclose(fp);
	return status;
}

int semanage_direct_access_check(semanage_handle_t * sh)
{
	if (semanage_check_init(sh, sh->conf->store_root_path))
		return -1;

	return semanage_store_access_check();
}

int semanage_direct_mls_enabled(semanage_handle_t * sh)
{
	sepol_policydb_t *p = NULL;
	int retval;

	retval = sepol_policydb_create(&p);
	if (retval < 0)
		goto cleanup;

	retval = semanage_read_policydb(sh, p, SEMANAGE_STORE_KERNEL);
	if (retval < 0)
		goto cleanup;

	retval = sepol_policydb_mls_enabled(p);
cleanup:
	sepol_policydb_free(p);
	return retval;
}

static int semanage_direct_get_module_info(semanage_handle_t *sh,
					   const semanage_module_key_t *modkey,
					   semanage_module_info_t **modinfo)
{
	assert(sh);
	assert(modkey);
	assert(modinfo);

	int status = 0;
	int ret = 0;

	char fn[PATH_MAX];
	FILE *fp = NULL;
	size_t size = 0;
	struct stat sb;
	char *tmp = NULL;

	int i = 0;

	semanage_module_info_t *modinfos = NULL;
	int modinfos_len = 0;
	semanage_module_info_t *highest = NULL;

	/* check module name */
	ret = semanage_module_validate_name(modkey->name);
	if (ret < 0) {
		errno = 0;
		ERR(sh, "Name %s is invalid.", modkey->name);
		status = -1;
		goto cleanup;
	}

	/* if priority == 0, then find the highest priority available */
	if (modkey->priority == 0) {
		ret = semanage_direct_list_all(sh, &modinfos, &modinfos_len);
		if (ret != 0) {
			status = -1;
			goto cleanup;
		}

		for (i = 0; i < modinfos_len; i++) {
			ret = strcmp(modinfos[i].name, modkey->name);
			if (ret == 0) {
				highest = &modinfos[i];
				break;
			}
		}

		if (highest == NULL) {
			status = -1;
			goto cleanup;
		}

		ret = semanage_module_info_create(sh, modinfo);
		if (ret != 0) {
			status = -1;
			goto cleanup;
		}

		ret = semanage_module_info_clone(sh, highest, *modinfo);
		if (ret != 0) {
			status = -1;
		}

		/* skip to cleanup, module was found */
		goto cleanup;
	}

	/* check module priority */
	ret = semanage_module_validate_priority(modkey->priority);
	if (ret != 0) {
		errno = 0;
		ERR(sh, "Priority %d is invalid.", modkey->priority);
		status = -1;
		goto cleanup;
	}

	/* copy in key values */
	ret = semanage_module_info_create(sh, modinfo);
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

	ret = semanage_module_info_set_priority(sh, *modinfo, modkey->priority);
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

	ret = semanage_module_info_set_name(sh, *modinfo, modkey->name);
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

	/* lookup module ext */
	ret = semanage_module_get_path(sh,
				       *modinfo,
				       SEMANAGE_MODULE_PATH_LANG_EXT,
				       fn,
				       sizeof(fn));
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

	fp = fopen(fn, "r");

	if (fp == NULL) {
		ERR(sh,
		    "Unable to open %s module lang ext file at %s.",
		    (*modinfo)->name, fn);
		status = -1;
		goto cleanup;
	}

	/* set module ext */
	if (getline(&tmp, &size, fp) < 0) {
		ERR(sh,
		    "Unable to read %s module lang ext file.",
		    (*modinfo)->name);
		status = -1;
		goto cleanup;
	}

	ret = semanage_module_info_set_lang_ext(sh, *modinfo, tmp);
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}
	free(tmp);
	tmp = NULL;

	if (fclose(fp) != 0) {
		ERR(sh,
		    "Unable to close %s module lang ext file.",
		    (*modinfo)->name);
		status = -1;
		goto cleanup;
	}

	fp = NULL;

	/* lookup enabled/disabled status */
	ret = semanage_module_get_path(sh,
				       *modinfo,
				       SEMANAGE_MODULE_PATH_DISABLED,
				       fn,
				       sizeof(fn));
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

	/* set enabled/disabled status */
	if (stat(fn, &sb) < 0) {
		if (errno != ENOENT) {
			ERR(sh, "Unable to access %s: %s\n", fn, strerror(errno));
			status = -1;
			goto cleanup;
		}

		ret = semanage_module_info_set_enabled(sh, *modinfo, 1);
		if (ret != 0) {
			status = -1;
			goto cleanup;
		}
	}
	else {
		ret = semanage_module_info_set_enabled(sh, *modinfo, 0);
		if (ret != 0) {
			status = -1;
			goto cleanup;
		}
	}

cleanup:
	free(tmp);

	if (modinfos != NULL) {
		for (i = 0; i < modinfos_len; i++) {
			semanage_module_info_destroy(sh, &modinfos[i]);
		}
		free(modinfos);
	}

	if (fp != NULL) fclose(fp);
	return status;
}

static int semanage_direct_set_module_info(semanage_handle_t *sh,
					   const semanage_module_info_t *modinfo)
{
	int status = 0;
	int ret = 0;

	char fn[PATH_MAX];
	const char *path = NULL;
	int enabled = 0;
	semanage_module_info_t *modinfo_tmp = NULL;

	semanage_module_key_t modkey;
	ret = semanage_module_key_init(sh, &modkey);
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

	/* check transaction */
	if (!sh->is_in_transaction) {
		if (semanage_begin_transaction(sh) < 0) {
			status = -1;
			goto cleanup;
		}
	}

	/* validate module */
	ret = semanage_module_info_validate(modinfo);
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

	sh->modules_modified = 1;

	/* check for modules path, create if missing */
	path = semanage_path(SEMANAGE_TMP, SEMANAGE_MODULES);

	ret = semanage_mkdir(sh, path);
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

	/* write priority */
	ret = semanage_module_get_path(sh,
				       modinfo,
				       SEMANAGE_MODULE_PATH_PRIORITY,
				       fn,
				       sizeof(fn));
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

	ret = semanage_mkdir(sh, fn);
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

	/* write name */
	ret = semanage_module_get_path(sh,
				       modinfo,
				       SEMANAGE_MODULE_PATH_NAME,
				       fn,
				       sizeof(fn));
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

	ret = semanage_mkdir(sh, fn);
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

	/* write ext */
	ret = semanage_direct_write_langext(sh, modinfo->lang_ext, modinfo);
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

	/* write enabled/disabled status */

	/* check for disabled path, create if missing */
	path = semanage_path(SEMANAGE_TMP, SEMANAGE_MODULES_DISABLED);

	ret = semanage_mkdir(sh, path);
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

	ret = semanage_module_get_path(sh,
				       modinfo,
				       SEMANAGE_MODULE_PATH_DISABLED,
				       fn,
				       sizeof(fn));
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

	ret = semanage_module_key_set_name(sh, &modkey, modinfo->name);
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

	if (modinfo->enabled == -1) {
		/* default to enabled */
		enabled = 1;

		/* check if a module is already installed */
		ret = semanage_module_get_module_info(sh,
						      &modkey,
						      &modinfo_tmp);
		if (ret == 0) {
			/* set enabled status to current one */
			enabled = modinfo_tmp->enabled;
		}
	}
	else {
		enabled = modinfo->enabled;
	}

	ret = semanage_module_set_enabled(sh, &modkey, enabled);
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

cleanup:
	semanage_module_key_destroy(sh, &modkey);

	semanage_module_info_destroy(sh, modinfo_tmp);
	free(modinfo_tmp);

	return status;
}

static int semanage_priorities_filename_select(const struct dirent *d)
{
	if (d->d_name[0] == '.' ||
	    strcmp(d->d_name, "disabled") == 0)
		return 0;
	return 1;
}

static int semanage_modules_filename_select(const struct dirent *d)
{
	if (d->d_name[0] == '.')
		return 0;
	return 1;
}

static int semanage_direct_list_all(semanage_handle_t *sh,
				    semanage_module_info_t **modinfos,
				    int *modinfos_len)
{
	assert(sh);
	assert(modinfos);
	assert(modinfos_len);

	int status = 0;
	int ret = 0;

	int i = 0;
	int j = 0;

	*modinfos = NULL;
	*modinfos_len = 0;
	void *tmp = NULL;

	const char *toplevel = NULL;

	struct dirent **priorities = NULL;
	int priorities_len = 0;
	char priority_path[PATH_MAX];

	struct dirent **modules = NULL;
	int modules_len = 0;

	uint16_t priority = 0;

	semanage_module_info_t *modinfo_tmp = NULL;

	semanage_module_info_t modinfo;
	ret = semanage_module_info_init(sh, &modinfo);
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

	if (sh->is_in_transaction) {
		toplevel = semanage_path(SEMANAGE_TMP, SEMANAGE_MODULES);
	} else {
		toplevel = semanage_path(SEMANAGE_ACTIVE, SEMANAGE_MODULES);
	}

	/* find priorities */
	priorities_len = scandir(toplevel,
				 &priorities,
				 semanage_priorities_filename_select,
				 versionsort);
	if (priorities_len == -1) {
		ERR(sh, "Error while scanning directory %s.", toplevel);
		status = -1;
		goto cleanup;
	}

	/* for each priority directory */
	/* loop through in reverse so that highest priority is first */
	for (i = priorities_len - 1; i >= 0; i--) {
		/* convert priority string to uint16_t */
		ret = semanage_string_to_priority(priorities[i]->d_name,
						  &priority);
		if (ret != 0) {
			status = -1;
			goto cleanup;
		}

		/* set our priority */
		ret = semanage_module_info_set_priority(sh,
							&modinfo,
							priority);
		if (ret != 0) {
			status = -1;
			goto cleanup;
		}

		/* get the priority path */
		ret = semanage_module_get_path(sh,
					       &modinfo,
					       SEMANAGE_MODULE_PATH_PRIORITY,
					       priority_path,
					       sizeof(priority_path));
		if (ret != 0) {
			status = -1;
			goto cleanup;
		}

		/* cleanup old modules */
		if (modules != NULL) {
			for (j = 0; j < modules_len; j++) {
				free(modules[j]);
				modules[j] = NULL;
			}
			free(modules);
			modules = NULL;
			modules_len = 0;
		}

		/* find modules at this priority */
		modules_len = scandir(priority_path,
				      &modules,
				      semanage_modules_filename_select,
				      versionsort);
		if (modules_len == -1) {
			ERR(sh,
			    "Error while scanning directory %s.",
			    priority_path);
			status = -1;
			goto cleanup;
		}

		if (modules_len == 0) continue;

		/* add space for modules */
		tmp = realloc(*modinfos,
			      sizeof(semanage_module_info_t) *
				(*modinfos_len + modules_len));
		if (tmp == NULL) {
			ERR(sh, "Error allocating memory for module array.");
			status = -1;
			goto cleanup;
		}
		*modinfos = tmp;

		/* for each module directory */
		for(j = 0; j < modules_len; j++) {
			/* set module name */
			ret = semanage_module_info_set_name(
					sh,
					&modinfo,
					modules[j]->d_name);
			if (ret != 0) {
				status = -1;
				goto cleanup;
			}

			/* get module values */
			ret = semanage_direct_get_module_info(
					sh,
					(const semanage_module_key_t *)
						(&modinfo),
					&modinfo_tmp);
			if (ret != 0) {
				status = -1;
				goto cleanup;
			}

			/* copy into array */
			ret = semanage_module_info_init(
					sh,
					&((*modinfos)[*modinfos_len]));
			if (ret != 0) {
				status = -1;
				goto cleanup;
			}

			ret = semanage_module_info_clone(
					sh,
					modinfo_tmp,
					&((*modinfos)[*modinfos_len]));
			if (ret != 0) {
				status = -1;
				goto cleanup;
			}

			semanage_module_info_destroy(sh, modinfo_tmp);
			free(modinfo_tmp);
			modinfo_tmp = NULL;

			*modinfos_len += 1;
		}
	}

cleanup:
	semanage_module_info_destroy(sh, &modinfo);

	if (priorities != NULL) {
		for (i = 0; i < priorities_len; i++) {
			free(priorities[i]);
		}
		free(priorities);
	}

	if (modules != NULL) {
		for (i = 0; i < modules_len; i++) {
			free(modules[i]);
		}
		free(modules);
	}

	semanage_module_info_destroy(sh, modinfo_tmp);
	free(modinfo_tmp);
	modinfo_tmp = NULL;

	if (status != 0) {
		if (modinfos != NULL) {
			for (i = 0; i < *modinfos_len; i++) {
				semanage_module_info_destroy(
						sh, 
						&(*modinfos)[i]);
			}
			free(*modinfos);
			*modinfos = NULL;
			*modinfos_len = 0;
		}
	}

	return status;
}

static int semanage_direct_install_info(semanage_handle_t *sh,
					const semanage_module_info_t *modinfo,
					char *data,
					size_t data_len)
{
	assert(sh);
	assert(modinfo);
	assert(data);

	int status = 0;
	int ret = 0;
	int type;
	struct stat sb;

	char path[PATH_MAX];
	mode_t mask = umask(0077);

	semanage_module_info_t *higher_info = NULL;
	semanage_module_key_t higher_key;
	ret = semanage_module_key_init(sh, &higher_key);
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

	/* validate module info */
	ret = semanage_module_info_validate(modinfo);
	if (ret != 0) {
		ERR(sh, "%s failed module validation.\n", modinfo->name);
		status = -2;
		goto cleanup;
	}

	/* Check for higher priority module and warn if there is one as
	 * it will override the module currently being installed.
	 */
	ret = semanage_module_key_set_name(sh, &higher_key, modinfo->name);
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

	ret = semanage_direct_get_module_info(sh, &higher_key, &higher_info);
	if (ret == 0) {
		if (higher_info->priority > modinfo->priority) {
			errno = 0;
			WARN(sh,
			     "A higher priority %s module exists at priority %d and will override the module currently being installed at priority %d.",
			     modinfo->name,
			     higher_info->priority,
			     modinfo->priority);
		}
		else if (higher_info->priority < modinfo->priority) {
			errno = 0;
			INFO(sh,
			     "Overriding %s module at lower priority %d with module at priority %d.",
			     modinfo->name,
			     higher_info->priority,
			     modinfo->priority);
		}

		if (higher_info->enabled == 0 && modinfo->enabled == -1) {
			errno = 0;
			WARN(sh,
			     "%s module will be disabled after install as there is a disabled instance of this module present in the system.",
			     modinfo->name);
		}
	}

	/* set module meta data */
	ret = semanage_direct_set_module_info(sh, modinfo);
	if (ret != 0) {
		status = -2;
		goto cleanup;
	}

	/* install module source file */
	if (!strcasecmp(modinfo->lang_ext, "cil")) {
		type = SEMANAGE_MODULE_PATH_CIL;
	} else {
		type = SEMANAGE_MODULE_PATH_HLL;
	}
	ret = semanage_module_get_path(
			sh,
			modinfo,
			type,
			path,
			sizeof(path));
	if (ret != 0) {
		status = -3;
		goto cleanup;
	}

	ret = bzip(sh, path, data, data_len);
	if (ret <= 0) {
		ERR(sh, "Error while writing to %s.", path);
		status = -3;
		goto cleanup;
	}
	
	/* if this is an HLL, delete the CIL cache if it exists so it will get recompiled */
	if (type == SEMANAGE_MODULE_PATH_HLL) {
		ret = semanage_module_get_path(
				sh,
				modinfo,
				SEMANAGE_MODULE_PATH_CIL,
				path,
				sizeof(path));
		if (ret != 0) {
			status = -3;
			goto cleanup;
		}

		if (stat(path, &sb) == 0) {
			ret = unlink(path);
			if (ret != 0) {
				ERR(sh, "Error while removing cached CIL file %s: %s", path, strerror(errno));
				status = -3;
				goto cleanup;
			}
		}
	}

cleanup:
	semanage_module_key_destroy(sh, &higher_key);
	semanage_module_info_destroy(sh, higher_info);
	free(higher_info);
	umask(mask);

	return status;
}

static int semanage_direct_remove_key(semanage_handle_t *sh,
				      const semanage_module_key_t *modkey)
{
	assert(sh);
	assert(modkey);

	int status = 0;
	int ret = 0;

	char path[PATH_MAX];
	semanage_module_info_t *modinfo = NULL;

	semanage_module_key_t modkey_tmp;
	ret = semanage_module_key_init(sh, &modkey_tmp);
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

	/* validate module key */
	ret = semanage_module_validate_priority(modkey->priority);
	if (ret != 0) {
		errno = 0;
		ERR(sh, "Priority %d is invalid.", modkey->priority);
		status = -1;
		goto cleanup;
	}

	ret = semanage_module_validate_name(modkey->name);
	if (ret != 0) {
		errno = 0;
		ERR(sh, "Name %s is invalid.", modkey->name);
		status = -1;
		goto cleanup;
	}

	ret = semanage_module_key_set_name(sh, &modkey_tmp, modkey->name);
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

	/* get module path */
	ret = semanage_module_get_path(
			sh,
			(const semanage_module_info_t *)modkey,
			SEMANAGE_MODULE_PATH_NAME,
			path,
			sizeof(path));
	if (ret != 0) {
		status = -2;
		goto cleanup;
	}

	/* remove directory */
	ret = semanage_remove_directory(path);
	if (ret != 0) {
		ERR(sh, "Unable to remove module %s at priority %d.", modkey->name, modkey->priority);
		status = -2;
		goto cleanup;
	}

	/* check if its the last module at any priority */
	ret = semanage_module_get_module_info(sh, &modkey_tmp, &modinfo);
	if (ret != 0) {
		/* info that no other module will override */
		errno = 0;
		INFO(sh,
		     "Removing last %s module (no other %s module exists at another priority).",
		     modkey->name,
		     modkey->name);

		/* remove disabled status file */
		ret = semanage_module_get_path(
				sh,
				(const semanage_module_info_t *)modkey,
				SEMANAGE_MODULE_PATH_DISABLED,
				path,
				sizeof(path));
		if (ret != 0) {
			status = -1;
			goto cleanup;
		}

		struct stat sb;
		if (stat(path, &sb) == 0) {
			ret = unlink(path);
			if (ret != 0) {
				status = -1;
				goto cleanup;
			}
		}
	}
	else {
		/* if a lower priority module is going to become active */
		if (modkey->priority > modinfo->priority) {
			/* inform what the new active module will be */
			errno = 0;
			INFO(sh,
			     "%s module at priority %d is now active.",
			     modinfo->name,
			     modinfo->priority);
		}
	}

cleanup:
	semanage_module_key_destroy(sh, &modkey_tmp);

	semanage_module_info_destroy(sh, modinfo);
	free(modinfo);

	return status;
}

