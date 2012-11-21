/* Author: Jason Tang	  <jtang@tresys.com>
 *         Christopher Ashworth <cashworth@tresys.com>
 *
 * Copyright (C) 2004-2006 Tresys Technology, LLC
 * Copyright (C) 2005-2011 Red Hat, Inc.
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

#include "user_internal.h"
#include "seuser_internal.h"
#include "port_internal.h"
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

static void semanage_direct_destroy(semanage_handle_t * sh);
static int semanage_direct_disconnect(semanage_handle_t * sh);
static int semanage_direct_begintrans(semanage_handle_t * sh);
static int semanage_direct_commit(semanage_handle_t * sh);
static int semanage_direct_install(semanage_handle_t * sh, char *data,
				   size_t data_len);
static int semanage_direct_install_file(semanage_handle_t * sh, const char *module_name);
static int semanage_direct_upgrade(semanage_handle_t * sh, char *data,
				   size_t data_len);
static int semanage_direct_upgrade_file(semanage_handle_t * sh, const char *module_name);
static int semanage_direct_install_base(semanage_handle_t * sh, char *base_data,
					size_t data_len);
static int semanage_direct_install_base_file(semanage_handle_t * sh, const char *module_name);
static int semanage_direct_enable(semanage_handle_t * sh, char *module_name);
static int semanage_direct_disable(semanage_handle_t * sh, char *module_name);
static int semanage_direct_remove(semanage_handle_t * sh, char *module_name);
static int semanage_direct_list(semanage_handle_t * sh,
				semanage_module_info_t ** modinfo,
				int *num_modules);

static struct semanage_policy_table direct_funcs = {
	.get_serial = semanage_direct_get_serial,
	.destroy = semanage_direct_destroy,
	.disconnect = semanage_direct_disconnect,
	.begin_trans = semanage_direct_begintrans,
	.commit = semanage_direct_commit,
	.install = semanage_direct_install,
	.install_file = semanage_direct_install_file,
	.upgrade = semanage_direct_upgrade,
	.upgrade_file = semanage_direct_upgrade_file,
	.install_base = semanage_direct_install_base,
	.install_base_file = semanage_direct_install_base_file,
	.enable = semanage_direct_enable,
	.disable = semanage_direct_disable,
	.remove = semanage_direct_remove,
	.list = semanage_direct_list
};

int semanage_direct_is_managed(semanage_handle_t * sh)
{
	char polpath[PATH_MAX];

	snprintf(polpath, PATH_MAX, "%s%s", semanage_selinux_path(),
		 sh->conf->store_path);

	if (semanage_check_init(polpath))
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
	char polpath[PATH_MAX];
	const char *path;

	snprintf(polpath, PATH_MAX, "%s%s", semanage_selinux_path(),
		 sh->conf->store_path);

	if (semanage_check_init(polpath))
		goto err;

	if (sh->create_store)
		if (semanage_create_store(sh, 1))
			goto err;

	if (semanage_access_check(sh) < SEMANAGE_CAN_READ)
		goto err;

	sh->u.direct.translock_file_fd = -1;
	sh->u.direct.activelock_file_fd = -1;

	/* set up function pointers */
	sh->funcs = &direct_funcs;

	/* Object databases: local modifications */
	if (user_base_file_dbase_init(sh,
				      semanage_fname(SEMANAGE_USERS_BASE_LOCAL),
				      semanage_user_base_dbase_local(sh)) < 0)
		goto err;

	if (user_extra_file_dbase_init(sh,
				       semanage_fname
				       (SEMANAGE_USERS_EXTRA_LOCAL),
				       semanage_user_extra_dbase_local(sh)) < 0)
		goto err;

	if (user_join_dbase_init(sh,
				 semanage_user_base_dbase_local(sh),
				 semanage_user_extra_dbase_local(sh),
				 semanage_user_dbase_local(sh)) < 0)
		goto err;

	if (port_file_dbase_init(sh,
				 semanage_fname(SEMANAGE_PORTS_LOCAL),
				 semanage_port_dbase_local(sh)) < 0)
		goto err;

	if (iface_file_dbase_init(sh,
				  semanage_fname(SEMANAGE_INTERFACES_LOCAL),
				  semanage_iface_dbase_local(sh)) < 0)
		goto err;

	if (bool_file_dbase_init(sh,
				 semanage_fname(SEMANAGE_BOOLEANS_LOCAL),
				 semanage_bool_dbase_local(sh)) < 0)
		goto err;

	if (fcontext_file_dbase_init(sh,
				     semanage_fname(SEMANAGE_FC_LOCAL),
				     semanage_fcontext_dbase_local(sh)) < 0)
		goto err;

	if (seuser_file_dbase_init(sh,
				   semanage_fname(SEMANAGE_SEUSERS_LOCAL),
				   semanage_seuser_dbase_local(sh)) < 0)
		goto err;

	if (node_file_dbase_init(sh,
				 semanage_fname(SEMANAGE_NODES_LOCAL),
				 semanage_node_dbase_local(sh)) < 0)
		goto err;

	/* Object databases: local modifications + policy */
	if (user_base_policydb_dbase_init(sh,
					  semanage_user_base_dbase_policy(sh)) <
	    0)
		goto err;

	if (user_extra_file_dbase_init(sh,
				       semanage_fname(SEMANAGE_USERS_EXTRA),
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

	if (iface_policydb_dbase_init(sh, semanage_iface_dbase_policy(sh)) < 0)
		goto err;

	if (bool_policydb_dbase_init(sh, semanage_bool_dbase_policy(sh)) < 0)
		goto err;

	if (fcontext_file_dbase_init(sh,
				     semanage_fname(SEMANAGE_FC),
				     semanage_fcontext_dbase_policy(sh)) < 0)
		goto err;

	if (seuser_file_dbase_init(sh,
				   semanage_fname(SEMANAGE_SEUSERS),
				   semanage_seuser_dbase_policy(sh)) < 0)
		goto err;

	if (node_policydb_dbase_init(sh, semanage_node_dbase_policy(sh)) < 0)
		goto err;

	/* Active kernel policy */
	if (bool_activedb_dbase_init(sh, semanage_bool_dbase_active(sh)) < 0)
		goto err;

	/* set the disable dontaudit value */
	path = semanage_path(SEMANAGE_ACTIVE, SEMANAGE_DISABLE_DONTAUDIT);
	if (access(path, F_OK) == 0)
		sepol_set_disable_dontaudit(sh->sepolh, 1);
	else
		sepol_set_disable_dontaudit(sh->sepolh, 0);

	return STATUS_SUCCESS;

      err:
	ERR(sh, "could not establish direct connection");
	return STATUS_ERR;
}

static void semanage_direct_destroy(semanage_handle_t * sh
					__attribute__ ((unused)))
{
	/* do nothing */
	sh = NULL;
}

static int semanage_direct_disconnect(semanage_handle_t * sh)
{
	/* destroy transaction */
	if (sh->is_in_transaction) {
		/* destroy sandbox */
		if (semanage_remove_directory
		    (semanage_path(SEMANAGE_TMP, SEMANAGE_TOPLEVEL)) < 0) {
			ERR(sh, "Could not cleanly remove sandbox %s.",
			    semanage_path(SEMANAGE_TMP, SEMANAGE_TOPLEVEL));
			return -1;
		}
		semanage_release_trans_lock(sh);
	}

	/* Release object databases: local modifications */
	user_base_file_dbase_release(semanage_user_base_dbase_local(sh));
	user_extra_file_dbase_release(semanage_user_extra_dbase_local(sh));
	user_join_dbase_release(semanage_user_dbase_local(sh));
	port_file_dbase_release(semanage_port_dbase_local(sh));
	iface_file_dbase_release(semanage_iface_dbase_local(sh));
	bool_file_dbase_release(semanage_bool_dbase_local(sh));
	fcontext_file_dbase_release(semanage_fcontext_dbase_local(sh));
	seuser_file_dbase_release(semanage_seuser_dbase_local(sh));
	node_file_dbase_release(semanage_node_dbase_local(sh));

	/* Release object databases: local modifications + policy */
	user_base_policydb_dbase_release(semanage_user_base_dbase_policy(sh));
	user_extra_file_dbase_release(semanage_user_extra_dbase_policy(sh));
	user_join_dbase_release(semanage_user_dbase_policy(sh));
	port_policydb_dbase_release(semanage_port_dbase_policy(sh));
	iface_policydb_dbase_release(semanage_iface_dbase_policy(sh));
	bool_policydb_dbase_release(semanage_bool_dbase_policy(sh));
	fcontext_file_dbase_release(semanage_fcontext_dbase_policy(sh));
	seuser_file_dbase_release(semanage_seuser_dbase_policy(sh));
	node_policydb_dbase_release(semanage_node_dbase_policy(sh));

	/* Release object databases: active kernel policy */
	bool_activedb_dbase_release(semanage_bool_dbase_active(sh));

	return 0;
}

static int semanage_direct_begintrans(semanage_handle_t * sh)
{

	if (semanage_access_check(sh) != SEMANAGE_CAN_WRITE) {
		return -1;
	}
	if (semanage_get_trans_lock(sh) < 0) {
		return -1;
	}
	if ((semanage_make_sandbox(sh)) < 0) {
		return -1;
	}
	return 0;
}

/********************* utility functions *********************/

/* Takes a module stored in 'module_data' and parses its headers.
 * Sets reference variables 'filename' to module's fully qualified
 * path name into the sandbox, 'module_name' to module's name, and
 * 'version' to module's version.  The caller is responsible for
 * free()ing 'filename', 'module_name', and 'version'; they will be
 * set to NULL upon entering this function.  Returns 0 on success, -1
 * if out of memory, or -2 if data did not represent a module.
 */
static int parse_module_headers(semanage_handle_t * sh, char *module_data,
				size_t data_len, char **module_name,
				char **version, char **filename)
{
	struct sepol_policy_file *pf;
	int file_type;
	const char *module_path;
	*module_name = *version = *filename = NULL;

	if (sepol_policy_file_create(&pf)) {
		ERR(sh, "Out of memory!");
		return -1;
	}
	sepol_policy_file_set_mem(pf, module_data, data_len);
	sepol_policy_file_set_handle(pf, sh->sepolh);
	if (module_data == NULL ||
	    data_len == 0 ||
	    sepol_module_package_info(pf, &file_type, module_name,
				      version) == -1) {
		sepol_policy_file_free(pf);
		ERR(sh, "Could not parse module data.");
		return -2;
	}
	sepol_policy_file_free(pf);
	if (file_type != SEPOL_POLICY_MOD) {
		if (file_type == SEPOL_POLICY_BASE)
			ERR(sh,
			    "Received a base module, expected a non-base module.");
		else
			ERR(sh, "Data did not represent a module.");
		return -2;
	}
	if ((module_path =
	     semanage_path(SEMANAGE_TMP, SEMANAGE_MODULES)) == NULL) {
		return -1;
	}
	if (asprintf(filename, "%s/%s.pp", module_path, *module_name) == -1) {
		ERR(sh, "Out of memory!");
		return -1;
	}

	return 0;
}

/* Takes a base module stored in 'module_data' and parse its headers.
 * Returns 0 on success, -1 if out of memory, or -2 if data did not
 * represent a module.
 */
static int parse_base_headers(semanage_handle_t * sh,
			      char *module_data, size_t data_len)
{
	struct sepol_policy_file *pf;
	char *module_name = NULL, *version = NULL;
	int file_type;

	if (sepol_policy_file_create(&pf)) {
		ERR(sh, "Out of memory!");
		return -1;
	}
	sepol_policy_file_set_mem(pf, module_data, data_len);
	sepol_policy_file_set_handle(pf, sh->sepolh);
	if (module_data == NULL ||
	    data_len == 0 ||
	    sepol_module_package_info(pf, &file_type,
				      &module_name, &version) == -1) {
		sepol_policy_file_free(pf);
		ERR(sh, "Could not parse base module data.");
		return -2;
	}
	sepol_policy_file_free(pf);
	free(module_name);
	free(version);
	if (file_type != SEPOL_POLICY_BASE) {
		if (file_type == SEPOL_POLICY_MOD)
			ERR(sh,
			    "Received a non-base module, expected a base module.");
		else
			ERR(sh, "Data did not represent a module.");
		return -2;
	}
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
	BZFILE* b;
	size_t  nBuf;
	char    buf[1<<18];
	size_t  size = sizeof(buf);
	int     bzerror;
	size_t  total=0;

	if (!sh->conf->bzip_blocksize) {
		bzerror = fread(buf, 1, BZ2_MAGICLEN, f);
		rewind(f);
		if ((bzerror != BZ2_MAGICLEN) || memcmp(buf, BZ2_MAGICSTR, BZ2_MAGICLEN))
			return -1;
		/* fall through */
	}
	
	b = BZ2_bzReadOpen ( &bzerror, f, 0, sh->conf->bzip_small, NULL, 0 );
	if ( bzerror != BZ_OK ) {
		BZ2_bzReadClose ( &bzerror, b );
		return -1;
	}
	
	char *uncompress = realloc(NULL, size);
	
	while ( bzerror == BZ_OK) {
		nBuf = BZ2_bzRead ( &bzerror, b, buf, sizeof(buf));
		if (( bzerror == BZ_OK ) || ( bzerror == BZ_STREAM_END )) {
			if (total + nBuf > size) {
				size *= 2;
				uncompress = realloc(uncompress, size);
			}
			memcpy(&uncompress[total], buf, nBuf);
			total += nBuf;
		}
	}
	if ( bzerror != BZ_STREAM_END ) {
		BZ2_bzReadClose ( &bzerror, b );
		free(uncompress);
		return -1;
	}
	BZ2_bzReadClose ( &bzerror, b );

	*data = uncompress;
	return  total;
}

/* mmap() a file to '*data',
 *  If the file is bzip compressed map_file will uncompress 
 * the file into '*data'.
 * Returns the total number of bytes in memory .
 * Returns -1 if file could not be opened or mapped. */
static ssize_t map_file(semanage_handle_t *sh, int fd, char **data,
			int *compressed)
{
	ssize_t size = -1;
	char *uncompress;
	if ((size = bunzip(sh, fdopen(fd, "r"), &uncompress)) > 0) {
		*data = mmap(0, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
		if (*data == MAP_FAILED) {
			free(uncompress);
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

	return size;
}

static int dupfile( const char *dest, int src_fd) {
	int dest_fd = -1;
	int retval = 0;
	int cnt;
	char    buf[1<<18];

	if (lseek(src_fd, 0, SEEK_SET)  == -1 ) return -1;

	if ((dest_fd = open(dest, O_WRONLY | O_CREAT | O_TRUNC,
			   S_IRUSR | S_IWUSR)) == -1) {
		return -1;
	}

	while (( retval == 0 ) && 
	       ( cnt = read(src_fd, buf, sizeof(buf)))> 0 ) {
		if (write(dest_fd, buf, cnt) < cnt) retval = -1;
	}
	close(dest_fd);
	return retval;
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

/* Writes a module (or a base) to the file given by a fully-qualified
 * 'filename'.	Returns 0 on success, -1 if file could not be written.
 */
static int semanage_write_module(semanage_handle_t * sh,
				 const char *filename,
				 sepol_module_package_t * package)
{
	struct sepol_policy_file *pf;
	FILE *outfile;
	int retval;
	if (sepol_policy_file_create(&pf)) {
		ERR(sh, "Out of memory!");
		return -1;
	}
	if ((outfile = fopen(filename, "wb")) == NULL) {
		sepol_policy_file_free(pf);
		ERR(sh, "Could not open %s for writing.", filename);
		return -1;
	}
	__fsetlocking(outfile, FSETLOCKING_BYCALLER);
	sepol_policy_file_set_fp(pf, outfile);
	sepol_policy_file_set_handle(pf, sh->sepolh);
	retval = sepol_module_package_write(package, pf);
	fclose(outfile);
	sepol_policy_file_free(pf);
	if (retval == -1) {
		ERR(sh, "Error while writing module to %s.", filename);
		return -1;
	}
	return 0;
}
static int semanage_direct_update_user_extra(semanage_handle_t * sh, sepol_module_package_t *base ) {
	const char *ofilename = NULL;
	int retval = -1;

	dbase_config_t *pusers_extra = semanage_user_extra_dbase_policy(sh);

	if (sepol_module_package_get_user_extra_len(base)) {
		ofilename = semanage_path(SEMANAGE_TMP, SEMANAGE_USERS_EXTRA);
		if (ofilename == NULL) {
			return retval;
		}
		retval = write_file(sh, ofilename,
				    sepol_module_package_get_user_extra(base),
				    sepol_module_package_get_user_extra_len(base));
		if (retval < 0)
			return retval;

		pusers_extra->dtable->drop_cache(pusers_extra->dbase);
		
	} else {
		retval =  pusers_extra->dtable->clear(sh, pusers_extra->dbase);
	}

	return retval;
}
	

static int semanage_direct_update_seuser(semanage_handle_t * sh, sepol_module_package_t *base ) {

	const char *ofilename = NULL;
	int retval = -1;

	dbase_config_t *pseusers = semanage_seuser_dbase_policy(sh);

	if (sepol_module_package_get_seusers_len(base)) {
		ofilename = semanage_path(SEMANAGE_TMP, SEMANAGE_SEUSERS);
		if (ofilename == NULL) {
			return -1;
		}
		retval = write_file(sh, ofilename,
				    sepol_module_package_get_seusers(base),
				    sepol_module_package_get_seusers_len(base));
		if (retval < 0)
			return retval;
		
		pseusers->dtable->drop_cache(pseusers->dbase);
		
	} else {
		retval = pseusers->dtable->clear(sh, pseusers->dbase);
	}
	return retval;
}

/********************* direct API functions ********************/

/* Commits all changes in sandbox to the actual kernel policy.
 * Returns commit number on success, -1 on error.
 */
static int semanage_direct_commit(semanage_handle_t * sh)
{
	char **mod_filenames = NULL;
	char *sorted_fc_buffer = NULL, *sorted_nc_buffer = NULL;
	size_t sorted_fc_buffer_len = 0, sorted_nc_buffer_len = 0;
	const char *linked_filename = NULL, *ofilename = NULL, *path;
	sepol_module_package_t *base = NULL;
	int retval = -1, num_modfiles = 0, i;
	sepol_policydb_t *out = NULL;

	/* Declare some variables */
	int modified = 0, fcontexts_modified, ports_modified,
	    seusers_modified, users_extra_modified, dontaudit_modified,
	    preserve_tunables_modified;
	dbase_config_t *users = semanage_user_dbase_local(sh);
	dbase_config_t *users_base = semanage_user_base_dbase_local(sh);
	dbase_config_t *pusers_base = semanage_user_base_dbase_policy(sh);
	dbase_config_t *users_extra = semanage_user_extra_dbase_local(sh);
	dbase_config_t *ports = semanage_port_dbase_local(sh);
	dbase_config_t *pports = semanage_port_dbase_policy(sh);
	dbase_config_t *bools = semanage_bool_dbase_local(sh);
	dbase_config_t *pbools = semanage_bool_dbase_policy(sh);
	dbase_config_t *ifaces = semanage_iface_dbase_local(sh);
	dbase_config_t *pifaces = semanage_iface_dbase_policy(sh);
	dbase_config_t *nodes = semanage_node_dbase_local(sh);
	dbase_config_t *pnodes = semanage_node_dbase_policy(sh);
	dbase_config_t *fcontexts = semanage_fcontext_dbase_local(sh);
	dbase_config_t *pfcontexts = semanage_fcontext_dbase_policy(sh);
	dbase_config_t *seusers = semanage_seuser_dbase_local(sh);

	/* Create or remove the disable_dontaudit flag file. */
	path = semanage_path(SEMANAGE_TMP, SEMANAGE_DISABLE_DONTAUDIT);
	if (access(path, F_OK) == 0)
		dontaudit_modified = !(sepol_get_disable_dontaudit(sh->sepolh) == 1);
	else
		dontaudit_modified = (sepol_get_disable_dontaudit(sh->sepolh) == 1);
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
	if (access(path, F_OK) == 0)
		preserve_tunables_modified = !(sepol_get_preserve_tunables(sh->sepolh) == 1);
	else
		preserve_tunables_modified = (sepol_get_preserve_tunables(sh->sepolh) == 1);
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

	/* Decide if anything was modified */
	fcontexts_modified = fcontexts->dtable->is_modified(fcontexts->dbase);
	seusers_modified = seusers->dtable->is_modified(seusers->dbase);
	users_extra_modified =
	    users_extra->dtable->is_modified(users_extra->dbase);
	ports_modified = ports->dtable->is_modified(ports->dbase);

	modified = sh->modules_modified;
	modified |= ports_modified;
	modified |= users->dtable->is_modified(users_base->dbase);
	modified |= bools->dtable->is_modified(bools->dbase);
	modified |= ifaces->dtable->is_modified(ifaces->dbase);
	modified |= nodes->dtable->is_modified(nodes->dbase);
	modified |= dontaudit_modified;
	modified |= preserve_tunables_modified;

	/* If there were policy changes, or explicitly requested, rebuild the policy */
	if (sh->do_rebuild || modified) {

		/* =================== Module expansion =============== */

		/* link all modules in the sandbox to the base module */
		retval = semanage_get_modules_names(sh, &mod_filenames, &num_modfiles);
		if (retval < 0)
			goto cleanup;
		retval = semanage_verify_modules(sh, mod_filenames, num_modfiles);
		if (retval < 0)
			goto cleanup;
		retval = semanage_link_sandbox(sh, &base);
		if (retval < 0)
			goto cleanup;

		/* write the linked base if we want to save or we have a
		 * verification program that wants it. */
		linked_filename = semanage_path(SEMANAGE_TMP, SEMANAGE_LINKED);
		if (linked_filename == NULL) {
			retval = -1;
			goto cleanup;
		}
		if (sh->conf->save_linked || sh->conf->linked_prog) {
			retval = semanage_write_module(sh, linked_filename, base);
			if (retval < 0)
				goto cleanup;
			retval = semanage_verify_linked(sh);
			if (retval < 0)
				goto cleanup;
			/* remove the linked policy if we only wrote it for the
			 * verification program. */
			if (!sh->conf->save_linked) {
				retval = unlink(linked_filename);
				if (retval < 0) {
					ERR(sh, "could not remove linked base %s",
					    linked_filename);
					goto cleanup;
				}
			}
		} else {
			/* Try to delete the linked copy - this is needed if
			 * the save_link option has changed to prevent the
			 * old linked copy from being copied forever. No error
			 * checking is done because this is likely to fail because
			 * the file does not exist - which is not an error. */
			unlink(linked_filename);
			errno = 0;
		}

		/* ==================== File-backed ================== */

		/* File Contexts */
		/* Sort the file contexts. */
		retval = semanage_fc_sort(sh, sepol_module_package_get_file_contexts(base),
					  sepol_module_package_get_file_contexts_len(base),
					  &sorted_fc_buffer, &sorted_fc_buffer_len);
		if (retval < 0)
			goto cleanup;

		/* Write the contexts (including template contexts) to a single file.  
		 * The buffer returned by the sort function has a trailing \0 character,
		 * which we do NOT want to write out to disk, so we pass sorted_fc_buffer_len-1. */
		ofilename = semanage_path(SEMANAGE_TMP, SEMANAGE_FC_TMPL);
		if (ofilename == NULL) {
			retval = -1;
			goto cleanup;
		}
		retval = write_file(sh, ofilename, sorted_fc_buffer,
				    sorted_fc_buffer_len - 1);
		if (retval < 0)
			goto cleanup;

		/* Split complete and template file contexts into their separate files. */
		retval = semanage_split_fc(sh);
		if (retval < 0)
			goto cleanup;

		pfcontexts->dtable->drop_cache(pfcontexts->dbase);

		retval = semanage_direct_update_seuser(sh, base );
		if (retval < 0)
			goto cleanup;

		retval = semanage_direct_update_user_extra(sh, base );
		if (retval < 0)
			goto cleanup;

		/* Netfilter Contexts */
		/* Sort the netfilter contexts. */
		retval = semanage_nc_sort
		    (sh, sepol_module_package_get_netfilter_contexts(base),
		     sepol_module_package_get_netfilter_contexts_len(base),
		     &sorted_nc_buffer, &sorted_nc_buffer_len);

		if (retval < 0)
			goto cleanup;

		/* Write the contexts to a single file.  The buffer returned by
		 * the sort function has a trailing \0 character, which we do
		 * NOT want to write out to disk, so we pass sorted_fc_buffer_len-1. */
		ofilename = semanage_path(SEMANAGE_TMP, SEMANAGE_NC);
		retval = write_file
		    (sh, ofilename, sorted_nc_buffer, sorted_nc_buffer_len - 1);

		if (retval < 0)
			goto cleanup;

		/* ==================== Policydb-backed ================ */

		/* Create new policy object, then attach to policy databases
		 * that work with a policydb */
		retval = semanage_expand_sandbox(sh, base, &out);
		if (retval < 0)
			goto cleanup;
	
		sepol_module_package_free(base);
		base = NULL;

		dbase_policydb_attach((dbase_policydb_t *) pusers_base->dbase,
				      out);
		dbase_policydb_attach((dbase_policydb_t *) pports->dbase, out);
		dbase_policydb_attach((dbase_policydb_t *) pifaces->dbase, out);
		dbase_policydb_attach((dbase_policydb_t *) pbools->dbase, out);
		dbase_policydb_attach((dbase_policydb_t *) pnodes->dbase, out);

		/* ============= Apply changes, and verify  =============== */

		retval = semanage_base_merge_components(sh);
		if (retval < 0)
			goto cleanup;

		retval = semanage_write_policydb(sh, out);
		if (retval < 0)
			goto cleanup;

		retval = semanage_verify_kernel(sh);
		if (retval < 0)
			goto cleanup;
	} else {
		retval = sepol_policydb_create(&out);
		if (retval < 0)
			goto cleanup;

		retval = semanage_read_policydb(sh, out);
		if (retval < 0)
			goto cleanup;
		
		if (seusers_modified || users_extra_modified) {
			retval = semanage_link_base(sh, &base);
			if (retval < 0)
				goto cleanup;

			if (seusers_modified) {
				retval = semanage_direct_update_seuser(sh, base );
				if (retval < 0)
					goto cleanup;
			}
			if (users_extra_modified) {
				/* Users_extra */
				retval = semanage_direct_update_user_extra(sh, base );
				if (retval < 0)
					goto cleanup;
			}

			sepol_module_package_free(base);
			base = NULL;
		}

		retval = semanage_base_merge_components(sh);
		if (retval < 0)
		  goto cleanup;

	}
	/* ======= Post-process: Validate non-policydb components ===== */

	/* Validate local modifications to file contexts.
	 * Note: those are still cached, even though they've been 
	 * merged into the main file_contexts. We won't check the 
	 * large file_contexts - checked at compile time */
	if (sh->do_rebuild || modified || fcontexts_modified) {
		retval = semanage_fcontext_validate_local(sh, out);
		if (retval < 0)
			goto cleanup;
	}

	/* Validate local seusers against policy */
	if (sh->do_rebuild || modified || seusers_modified) {
		retval = semanage_seuser_validate_local(sh, out);
		if (retval < 0)
			goto cleanup;
	}

	/* Validate local ports for overlap */
	if (sh->do_rebuild || ports_modified) {
		retval = semanage_port_validate_local(sh);
		if (retval < 0)
			goto cleanup;
	}

	/* ================== Write non-policydb components ========= */

	/* Commit changes to components */
	retval = semanage_commit_components(sh);
	if (retval < 0)
		goto cleanup;

	/* run genhomedircon if its enabled, this should be the last operation
	 * which requires the out policydb */
	if (!sh->conf->disable_genhomedircon) {
		if (out && (retval =
			semanage_genhomedircon(sh, out, sh->conf->usepasswd, sh->conf->ignoredirs)) != 0) {
			ERR(sh, "semanage_genhomedircon returned error code %d.",
			    retval);
			goto cleanup;
		}
	} else {
		WARN(sh, "WARNING: genhomedircon is disabled. \
                               See /etc/selinux/semanage.conf if you need to enable it.");
        }

	/* free out, if we don't free it before calling semanage_install_sandbox 
	 * then fork() may fail on low memory machines */
	sepol_policydb_free(out);
	out = NULL;

	if (sh->do_rebuild || modified || 
	    seusers_modified || fcontexts_modified || users_extra_modified) {
		retval = semanage_install_sandbox(sh);
	}

      cleanup:
	for (i = 0; mod_filenames != NULL && i < num_modfiles; i++) {
		free(mod_filenames[i]);
	}

	if (modified) {
		/* Detach from policydb, so it can be freed */
		dbase_policydb_detach((dbase_policydb_t *) pusers_base->dbase);
		dbase_policydb_detach((dbase_policydb_t *) pports->dbase);
		dbase_policydb_detach((dbase_policydb_t *) pifaces->dbase);
		dbase_policydb_detach((dbase_policydb_t *) pnodes->dbase);
		dbase_policydb_detach((dbase_policydb_t *) pbools->dbase);
	}

	free(mod_filenames);
	sepol_policydb_free(out);
	semanage_release_trans_lock(sh);

	free(sorted_fc_buffer);
	free(sorted_nc_buffer);

	/* regardless if the commit was successful or not, remove the
	   sandbox if it is still there */
	semanage_remove_directory(semanage_path
				  (SEMANAGE_TMP, SEMANAGE_TOPLEVEL));
	return retval;
}

/* Writes a module to the sandbox's module directory, overwriting any
 * previous module stored within.  Note that module data are not
 * free()d by this function; caller is responsible for deallocating it
 * if necessary.  Returns 0 on success, -1 if out of memory, -2 if the
 * data does not represent a valid module file, -3 if error while
 * writing file. */
static int semanage_direct_install(semanage_handle_t * sh,
				   char *data, size_t data_len)
{

	int retval;
	char *module_name = NULL, *version = NULL, *filename = NULL;
	if ((retval = parse_module_headers(sh, data, data_len,
					   &module_name, &version,
					   &filename)) != 0) {
		goto cleanup;
	}
	if (bzip(sh, filename, data, data_len) <= 0) {
		ERR(sh, "Error while writing to %s.", filename);
		retval = -3;
		goto cleanup;
	}
	retval = 0;
      cleanup:
	free(version);
	free(filename);
	free(module_name);
	return retval;
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
	int in_fd = -1;

	if ((in_fd = open(install_filename, O_RDONLY)) == -1) {
		return -1;
	}

	if ((data_len = map_file(sh, in_fd, &data, &compressed)) <= 0) {
		goto cleanup;
	}
		
	if (compressed) {
		char *module_name = NULL, *version = NULL, *filename = NULL;
		if ((retval = parse_module_headers(sh, data, data_len,
						   &module_name, &version,
						   &filename)) != 0) {
			goto cleanup;
		}

		if (data_len > 0) munmap(data, data_len);
		data_len = 0;
		retval = dupfile(filename, in_fd);
		free(version);
		free(filename);
		free(module_name);

	} else {
		retval = semanage_direct_install(sh, data, data_len);
	}

      cleanup:
	close(in_fd);
	if (data_len > 0) munmap(data, data_len);

	return retval;
}


static int get_direct_upgrade_filename(semanage_handle_t * sh,
				       char *data, size_t data_len, char **outfilename) {
	int i, retval, num_modules = 0;
	char *module_name = NULL, *version = NULL, *filename = NULL;
	semanage_module_info_t *modinfo = NULL;
	if ((retval = parse_module_headers(sh, data, data_len,
					   &module_name, &version,
					   &filename)) != 0) {
		goto cleanup;
	}
	if (semanage_direct_list(sh, &modinfo, &num_modules) < 0) {
		goto cleanup;
	}
	retval = -5;
	for (i = 0; i < num_modules; i++) {
		semanage_module_info_t *m =
		    semanage_module_list_nth(modinfo, i);
		if (strcmp(semanage_module_get_name(m), module_name) == 0) {
			if (strverscmp(version, semanage_module_get_version(m))
			    > 0) {
				retval = 0;
				break;
			} else {
				ERR(sh, "Previous module %s is same or newer.",
				    module_name);
				retval = -4;
				goto cleanup;
			}
		}
	}
      cleanup:
	free(version);
	free(module_name);
	for (i = 0; modinfo != NULL && i < num_modules; i++) {
		semanage_module_info_t *m =
		    semanage_module_list_nth(modinfo, i);
		semanage_module_info_datum_destroy(m);
	}
	free(modinfo);
	if (retval == 0) {
		*outfilename = filename;
	} else {
		free(filename);
	}
	return retval;
}

/* Similar to semanage_direct_install(), except that it checks that
 * there already exists a module with the same name and that the
 * module is an older version then the one in 'data'.  Returns 0 on
 * success, -1 if out of memory, -2 if the data does not represent a
 * valid module file, -3 if error while writing file or reading
 * modules directory, -4 if the previous module is same or newer than 'data', 
 * -5 if there does not exist an older module.
 */
static int semanage_direct_upgrade(semanage_handle_t * sh,
				   char *data, size_t data_len)
{
	char *filename = NULL;
	int retval = get_direct_upgrade_filename(sh,
						 data, data_len, 
						 &filename);
	if (retval == 0) {
		if (bzip(sh, filename, data, data_len) <= 0) {
			ERR(sh, "Error while writing to %s.", filename);
			retval = -3;
		}
		free(filename);
	}
	return retval;
}

/* Attempts to link a module to the sandbox's module directory, unlinking any
 * previous module stored within.  
 * Returns 0 on success, -1 if out of memory, -2 if the
 * data does not represent a valid module file, -3 if error while
 * writing file. */

static int semanage_direct_upgrade_file(semanage_handle_t * sh,
					const char *module_filename)
{
	int retval = -1;
	char *data = NULL;
	ssize_t data_len = 0;
	int compressed = 0;
	int in_fd = -1;

	if ((in_fd = open(module_filename, O_RDONLY)) == -1) {
		return -1;
	}

	if ((data_len = map_file(sh, in_fd, &data, &compressed)) <= 0) {
		goto cleanup;
	}

	if (compressed) {
		char *filename = NULL;
		retval = get_direct_upgrade_filename(sh,
					 	     data, data_len, 
						     &filename);
		
		if (retval != 0)  goto cleanup;

		retval = dupfile(filename, in_fd);
		free(filename);
	} else {
		retval = semanage_direct_upgrade(sh, data, data_len);
	}

      cleanup:
	close(in_fd);
	if (data_len > 0) munmap(data, data_len);

	return retval;
}

/* Writes a base module into a sandbox, overwriting any previous base
 * module.  Note that 'module_data' is not free()d by this function;
 * caller is responsible for deallocating it if necessary.  Returns 0
 * on success, -1 if out of memory, -2 if the data does not represent
 * a valid base module file, -3 if error while writing file.
 */
static int semanage_direct_install_base(semanage_handle_t * sh,
					char *base_data, size_t data_len)
{
	int retval = -1;
	const char *filename = NULL;
	if ((retval = parse_base_headers(sh, base_data, data_len)) != 0) {
		goto cleanup;
	}
	if ((filename = semanage_path(SEMANAGE_TMP, SEMANAGE_BASE)) == NULL) {
		goto cleanup;
	}
	if (bzip(sh, filename, base_data, data_len) <= 0) {
		ERR(sh, "Error while writing to %s.", filename);
		retval = -3;
		goto cleanup;
	}
	retval = 0;
      cleanup:
	return retval;
}

/* Writes a base module into a sandbox, overwriting any previous base
 * module.  
 * Returns 0 on success, -1 if out of memory, -2 if the data does not represent
 * a valid base module file, -3 if error while writing file.
 */
static int semanage_direct_install_base_file(semanage_handle_t * sh,
					     const char *install_filename)
{
	int retval = -1;
	char *data = NULL;
	ssize_t data_len = 0;
	int compressed = 0;
	int in_fd;

	if ((in_fd = open(install_filename, O_RDONLY)) == -1) {
		return -1;
	}

	if ((data_len = map_file(sh, in_fd, &data, &compressed)) <= 0) {
		goto cleanup;
	}
		
	if (compressed) {
		const char *filename = NULL;
		if ((retval = parse_base_headers(sh, data, data_len)) != 0) {
			goto cleanup;
		}
		if ((filename = semanage_path(SEMANAGE_TMP, SEMANAGE_BASE)) == NULL) {
			goto cleanup;
		}

		retval = dupfile(filename, in_fd);
	} else {
		retval = semanage_direct_install_base(sh, data, data_len);
	}

      cleanup:
	close(in_fd);
	if (data_len > 0) munmap(data, data_len);

	return retval;
}

static int get_module_name(semanage_handle_t * sh, char *modulefile, char **module_name) {
	FILE *fp = NULL;
	int retval = -1;
	char *data = NULL;
	char *version = NULL;
	ssize_t size;
	int type;
	struct sepol_policy_file *pf = NULL;

	if (sepol_policy_file_create(&pf)) {
		ERR(sh, "Out of memory!");
		goto cleanup;
	}
	sepol_policy_file_set_handle(pf, sh->sepolh);

	if ((fp = fopen(modulefile, "rb")) == NULL) {
		goto cleanup;
	}
	if ((size = bunzip(sh, fp, &data)) > 0) {
		sepol_policy_file_set_mem(pf, data, size);
	} else {
		rewind(fp);
		__fsetlocking(fp, FSETLOCKING_BYCALLER);
		sepol_policy_file_set_fp(pf, fp);
	}
	retval = sepol_module_package_info(pf, &type, module_name, &version);

cleanup:
	sepol_policy_file_free(pf);
	if (fp)
		fclose(fp);
	free(data);
	free(version);
	return retval;
}

static int get_module_file_by_name(semanage_handle_t * sh, const char *module_name, char **module_file) {
	int i, retval = -1;
	char **module_filenames = NULL;
	char *name = NULL;
	int num_mod_files;
	if (semanage_get_modules_names(sh, &module_filenames, &num_mod_files) ==
	    -1) {
		return -1;
	}
	for (i = 0; i < num_mod_files; i++) {
		int rc = get_module_name(sh, module_filenames[i], &name);
		if (rc < 0) 
			continue;
		if (strcmp(module_name, name) == 0) {
			*module_file = strdup(module_filenames[i]);
			if (*module_file) 
				retval = 0;
			goto cleanup;
		}
		free(name); name = NULL;
	}
	ERR(sh, "Module %s was not found.", module_name);
	retval = -2;		/* module not found */
      cleanup:
	free(name);
	for (i = 0; module_filenames != NULL && i < num_mod_files; i++) {
		free(module_filenames[i]);
	}
	free(module_filenames);
	return retval;
}

/* Enables a module from the sandbox.  Returns 0 on success, -1 if out
 * of memory, -2 if module not found or could not be enabled. */
static int semanage_direct_enable(semanage_handle_t * sh, char *module_name)
{
	char *module_filename = NULL;
	int retval = get_module_file_by_name(sh, module_name, &module_filename);
	if (retval <  0)
		return -1;		/* module not found */
	retval = semanage_enable_module(module_filename);
	if (retval < 0) {
		ERR(sh, "Could not enable module file %s.",
		    module_filename);
		retval = -2;
	}
	free(module_filename);
	return retval;
}

/* Disables a module from the sandbox.  Returns 0 on success, -1 if out
 * of memory, -2 if module not found or could not be enabled. */
static int semanage_direct_disable(semanage_handle_t * sh, char *module_name)
{
	char *module_filename = NULL;
	int retval = get_module_file_by_name(sh, module_name, &module_filename);	if (retval <  0)
		return -1;		/* module not found */
	retval = semanage_disable_module(module_filename);
	if (retval < 0) {
		ERR(sh, "Could not disable module file %s.",
		    module_filename);
		retval = -2;
	}
	free(module_filename);
	return retval;
}

/* Removes a module from the sandbox.  Returns 0 on success, -1 if out
 * of memory, -2 if module not found or could not be removed. */
static int semanage_direct_remove(semanage_handle_t * sh, char *module_name)
{
	char *module_filename = NULL;
	int retval = get_module_file_by_name(sh, module_name, &module_filename);
	if (retval <  0)
		return -1;		/* module not found */
	(void) semanage_enable_module(module_filename); /* Don't care if this fails */
	retval = unlink(module_filename);
	if (retval < 0) {
		ERR(sh, "Could not remove module file %s.",
		    module_filename);
		retval = -2;
	}
	free(module_filename);
	return retval;
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
	struct sepol_policy_file *pf = NULL;
	int i, retval = -1;
	char **module_filenames = NULL;
	int num_mod_files;
	*modinfo = NULL;
	*num_modules = 0;

	/* get the read lock when reading from the active
	   (non-transaction) directory */
	if (!sh->is_in_transaction)
		if (semanage_get_active_lock(sh) < 0)
			return -1;

	if (semanage_get_modules_names(sh, &module_filenames, &num_mod_files) ==
	    -1) {
		goto cleanup;
	}
	if (num_mod_files == 0) {
		retval = semanage_direct_get_serial(sh);
		goto cleanup;
	}

	if (sepol_policy_file_create(&pf)) {
		ERR(sh, "Out of memory!");
		goto cleanup;
	}
	sepol_policy_file_set_handle(pf, sh->sepolh);

	if ((*modinfo = calloc(num_mod_files, sizeof(**modinfo))) == NULL) {
		ERR(sh, "Out of memory!");
		goto cleanup;
	}

	for (i = 0; i < num_mod_files; i++) {
		FILE *fp;
		char *name = NULL, *version = NULL;
		int type;
		if ((fp = fopen(module_filenames[i], "rb")) == NULL) {
			/* could not open this module file, so don't
			 * report it */
			continue;
		}
		ssize_t size;
		char *data = NULL;
		int enabled = semanage_module_enabled(module_filenames[i]);

		if ((size = bunzip(sh, fp, &data)) > 0) {
			sepol_policy_file_set_mem(pf, data, size);
		} else {
			rewind(fp);
			__fsetlocking(fp, FSETLOCKING_BYCALLER);
			sepol_policy_file_set_fp(pf, fp);
		}
		if (sepol_module_package_info(pf, &type, &name, &version)) {
			fclose(fp);
			free(data);
			free(name);
			free(version);
			continue;
		}
		fclose(fp);
		free(data);
		if (type == SEPOL_POLICY_MOD) {
			(*modinfo)[*num_modules].name = name;
			(*modinfo)[*num_modules].version = version;
			(*modinfo)[*num_modules].enabled = enabled;
			(*num_modules)++;
		} else {
			/* file was not a module, so don't report it */
			free(name);
			free(version);
		}
	}
	retval = semanage_direct_get_serial(sh);

      cleanup:
	sepol_policy_file_free(pf);
	for (i = 0; module_filenames != NULL && i < num_mod_files; i++) {
		free(module_filenames[i]);
	}
	free(module_filenames);
	if (!sh->is_in_transaction) {
		semanage_release_active_lock(sh);
	}
	return retval;
}

int semanage_direct_access_check(semanage_handle_t * sh)
{
	char polpath[PATH_MAX];

	snprintf(polpath, PATH_MAX, "%s%s", semanage_selinux_path(),
		 sh->conf->store_path);

	if (semanage_check_init(polpath))
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

	retval = semanage_read_policydb(sh, p);
	if (retval < 0)
		goto cleanup;

	retval = sepol_policydb_mls_enabled(p);
cleanup:
	sepol_policydb_free(p);
	return retval;
}
