/* Authors: Karl MacMillan <kmacmillan@tresys.com>
 *	    Joshua Brindle <jbrindle@tresys.com>
 *	    Jason Tang <jtang@tresys.com>
 *	    Christopher Ashworth <cashworth@tresys.com>
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

#ifndef SEMANAGE_MODULE_STORE_H
#define SEMANAGE_MODULE_STORE_H

#include <stdbool.h>
#include <sys/time.h>
#include <sepol/module.h>
#include <sepol/cil/cil.h>
#include "handle.h"

enum semanage_store_defs {
	SEMANAGE_ACTIVE,
	SEMANAGE_PREVIOUS,
	SEMANAGE_TMP,
	SEMANAGE_NUM_STORES
};

/* sandbox filenames and paths */
enum semanage_sandbox_defs {
	SEMANAGE_TOPLEVEL,
	SEMANAGE_MODULES,
	SEMANAGE_LINKED,
	SEMANAGE_HOMEDIR_TMPL,
	SEMANAGE_FC_TMPL,
	SEMANAGE_COMMIT_NUM_FILE,
	SEMANAGE_IBPKEYS_LOCAL,
	SEMANAGE_IBENDPORTS_LOCAL,
	SEMANAGE_PORTS_LOCAL,
	SEMANAGE_INTERFACES_LOCAL,
	SEMANAGE_NODES_LOCAL,
	SEMANAGE_BOOLEANS_LOCAL,
	SEMANAGE_SEUSERS_LOCAL,
	SEMANAGE_SEUSERS_LINKED,
	SEMANAGE_USERS_BASE_LOCAL,
	SEMANAGE_USERS_EXTRA_LOCAL,
	SEMANAGE_USERS_EXTRA_LINKED,
	SEMANAGE_USERS_EXTRA,
	SEMANAGE_DISABLE_DONTAUDIT,
	SEMANAGE_PRESERVE_TUNABLES,
	SEMANAGE_MODULES_DISABLED,
	SEMANAGE_STORE_KERNEL,
	SEMANAGE_STORE_FC_LOCAL,
	SEMANAGE_STORE_FC_HOMEDIRS,
	SEMANAGE_STORE_FC,
	SEMANAGE_STORE_SEUSERS,
	SEMANAGE_STORE_NUM_PATHS
};

enum semanage_final_defs {
	SEMANAGE_FINAL_TMP,
	SEMANAGE_FINAL_SELINUX,
	SEMANAGE_FINAL_NUM
};

enum semanage_final_path_defs {
	SEMANAGE_FINAL_TOPLEVEL,
	SEMANAGE_FC,
	SEMANAGE_FC_BIN,
	SEMANAGE_FC_HOMEDIRS,
	SEMANAGE_FC_HOMEDIRS_BIN,
	SEMANAGE_FC_LOCAL,
	SEMANAGE_FC_LOCAL_BIN,
	SEMANAGE_KERNEL,
	SEMANAGE_NC,
	SEMANAGE_SEUSERS,
	SEMANAGE_FINAL_PATH_NUM
};

/* FIXME: this needs to be made a module store specific init and the
 * global configuration moved to another file.
 */
char *semanage_conf_path(void);

int semanage_check_init(semanage_handle_t *sh, const char *prefix);

extern const char *semanage_fname(enum semanage_sandbox_defs file_enum);

extern const char *semanage_path(enum semanage_store_defs store,
				 enum semanage_sandbox_defs file);

extern const char *semanage_final_path(enum semanage_final_defs root,
				       enum semanage_final_path_defs suffix);

int semanage_create_store(semanage_handle_t * sh, int create);

int semanage_store_access_check(void);

int semanage_remove_directory(const char *path);

int semanage_mkdir(semanage_handle_t *sh, const char *path);

int semanage_mkpath(semanage_handle_t *sh, const char *path);

int semanage_make_sandbox(semanage_handle_t * sh);

int semanage_make_final(semanage_handle_t * sh);

int semanage_get_cil_paths(semanage_handle_t * sh, semanage_module_info_t *modinfos,
			       int len, char ***filenames);

int semanage_get_active_modules(semanage_handle_t *sh,
			       semanage_module_info_t **modinfo, int *num_modules);


/* lock file routines */
int semanage_get_trans_lock(semanage_handle_t * sh);
int semanage_get_active_lock(semanage_handle_t * sh);
void semanage_release_trans_lock(semanage_handle_t * sh);
void semanage_release_active_lock(semanage_handle_t * sh);
int semanage_direct_get_serial(semanage_handle_t * sh);

int semanage_load_files(semanage_handle_t * sh,
			    cil_db_t *cildb, char **filenames, int num_modules);

int semanage_read_policydb(semanage_handle_t * sh,
			   sepol_policydb_t * policydb,
			   enum semanage_sandbox_defs file);

int semanage_write_policydb(semanage_handle_t * sh,
			    sepol_policydb_t * policydb,
			    enum semanage_sandbox_defs file);

int semanage_install_sandbox(semanage_handle_t * sh);

int semanage_verify_modules(semanage_handle_t * sh,
			    char **module_filenames, int num_modules);

int semanage_verify_linked(semanage_handle_t * sh);
int semanage_verify_kernel(semanage_handle_t * sh);
int semanage_split_fc(semanage_handle_t * sh);

/* sort file context routines */
int semanage_fc_sort(semanage_handle_t * sh,
		     const char *buf,
		     size_t buf_len,
		     char **sorted_buf, size_t * sorted_buf_len);

/* sort netfilter context routines */
int semanage_nc_sort(semanage_handle_t * sh,
		     const char *buf,
		     size_t buf_len,
		     char **sorted_buf, size_t * sorted_buf_len);

int semanage_copy_file(const char *src, const char *dst, mode_t mode,
		bool syncrequired);

#endif
