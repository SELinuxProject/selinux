/* Authors: Joshua Brindle  <jbrindle@tresys.com>
 *	    Jason Tang	    <jtang@tresys.com>
 *
 * Copyright (C) 2005 Tresys Technology, LLC
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

#ifndef _SEMANAGE_HANDLE_H_
#define _SEMANAGE_HANDLE_H_

#include <stdint.h>

/* All accesses with semanage are through a "semanage_handle".  The
 * handle may ultimately reference local config files,
 * the binary policy file, a module store, or a policy management server.
 */
struct semanage_handle;
typedef struct semanage_handle semanage_handle_t;

/* Create and return a semanage handle with a specific config path.
   The handle is initially in the disconnected state. */
semanage_handle_t *semanage_handle_create_with_path(const char *conf_name);

/* Create and return a semanage handle with the default config path.
   The handle is initially in the disconnected state. */
extern semanage_handle_t *semanage_handle_create(void);

/* Deallocate all space associated with a semanage_handle_t, including
 * the pointer itself.	CAUTION: this function does not disconnect
 * from the backend; be sure that a semanage_disconnect() was
 * previously called if the handle was connected. */
extern void semanage_handle_destroy(semanage_handle_t *);

/* This is the type of connection to the store, for now only
 * direct is supported */
enum semanage_connect_type {
	SEMANAGE_CON_INVALID = 0, SEMANAGE_CON_DIRECT,
	SEMANAGE_CON_POLSERV_LOCAL, SEMANAGE_CON_POLSERV_REMOTE
};

/* This function allows you to specify the store to  connect to.
 * It must be called after semanage_handle_create but before
 * semanage_connect. The argument should be the full path to the store.
 */
extern void semanage_select_store(semanage_handle_t * handle, const char *path,
				  enum semanage_connect_type storetype);

/* Just reload the policy */
extern int semanage_reload_policy(semanage_handle_t * handle);

/* set whether to reload the policy or not after a commit,
 * 1 for yes (default), 0 for no */
extern void semanage_set_reload(semanage_handle_t * handle, int do_reload);

/* set whether to rebuild the policy on commit, even if no
 * changes were performed.
 * 1 for yes, 0 for no (default) */
extern void semanage_set_rebuild(semanage_handle_t * handle, int do_rebuild);

/* set whether to rebuild the policy on commit when potential changes
 * to store files since last rebuild are detected,
 * 1 for yes (default), 0 for no */
extern void semanage_set_check_ext_changes(semanage_handle_t * handle, int do_check);

/* Fills *compiler_path with the location of the hll compiler sh->conf->compiler_directory_path
 * corresponding to lang_ext.
 * Upon success returns 0, -1 on error. */
extern int semanage_get_hll_compiler_path(semanage_handle_t *sh, const char *lang_ext, char **compiler_path);

/* create the store if it does not exist, this only has an effect on
 * direct connections and must be called before semanage_connect
 * 1 for yes, 0 for no (default) */
extern void semanage_set_create_store(semanage_handle_t * handle, int create_store);

/*Get whether or not dontaudits will be disabled upon commit */
extern int semanage_get_disable_dontaudit(semanage_handle_t * handle);

/* Set whether or not to disable dontaudits upon commit */
extern void semanage_set_disable_dontaudit(semanage_handle_t * handle, int disable_dontaudit);

/* Set whether or not to execute setfiles to check file contexts upon commit */
extern void semanage_set_check_contexts(semanage_handle_t * sh, int do_check_contexts);

/* Get the default priority. */
extern uint16_t semanage_get_default_priority(semanage_handle_t *sh);

/* Set the default priority. */
extern int semanage_set_default_priority(semanage_handle_t *sh, uint16_t priority);

/* Check whether policy is managed via libsemanage on this system.
 * Must be called prior to trying to connect.
 * Return 1 if policy is managed via libsemanage on this system,
 * 0 if policy is not managed, or -1 on error.
 */
extern int semanage_is_managed(semanage_handle_t *);

/* "Connect" to a manager based on the configuration and
 * associate the provided handle with the connection.
 * If the connect fails then this function returns a negative value,
 * else it returns zero.
 */
extern int semanage_connect(semanage_handle_t *);

/* Disconnect from the manager given by the handle.  If already
 * disconnected then this function does nothing.  Return 0 if
 * disconnected properly or already disconnected, negative value on
 * error. */
extern int semanage_disconnect(semanage_handle_t *);

/* Attempt to obtain a transaction lock on the manager.	 If another
 * process has the lock then this function may block, depending upon
 * the timeout value in the handle.
 *
 * Note that if the semanage_handle has not yet obtained a transaction
 * lock whenever a writer function is called, there will be an
 * implicit call to this function. */
extern int semanage_begin_transaction(semanage_handle_t *);

/* Attempt to commit all changes since this transaction began.	If the
 * commit is successful then increment the "policy sequence number"
 * and then release the transaction lock.  Return that policy number
 * afterwards, or -1 on error.
 */
extern int semanage_commit(semanage_handle_t *);

#define SEMANAGE_CAN_READ 1
#define SEMANAGE_CAN_WRITE 2
/* returns SEMANAGE_CAN_READ or SEMANAGE_CAN_WRITE if the store is readable
 * or writable, respectively. <0 if an error occurred */
extern int semanage_access_check(semanage_handle_t * sh);

/* returns 0 if not connected, 1 if connected */
extern int semanage_is_connected(semanage_handle_t * sh);

/* returns 1 if policy is MLS, 0 otherwise. */
extern int semanage_mls_enabled(semanage_handle_t *sh);

/* Change to alternate semanage root path */
extern int semanage_set_root(const char *path);

/* Get the current semanage root path */
extern const char * semanage_root(void);

/* Get whether or not needless unused branch of tunables would be preserved */
extern int semanage_get_preserve_tunables(semanage_handle_t * handle);

/* Set whether or not to preserve the needless unused branch of tunables */
extern void semanage_set_preserve_tunables(semanage_handle_t * handle, int preserve_tunables);

/* Get the flag value for whether or not caching is ignored for compiled CIL modules from HLL files */
extern int semanage_get_ignore_module_cache(semanage_handle_t *handle);

/* Set semanage_handle flag for whether or not to ignore caching of compiled CIL modules from HLL files */
extern void semanage_set_ignore_module_cache(semanage_handle_t *handle, int ignore_module_cache);

/* set the store root path for semanage output files */
extern void semanage_set_store_root(semanage_handle_t *sh, const char *store_root);

/* META NOTES
 *
 * For all functions a non-negative number indicates success. For some
 * functions a >=0 returned value is the "policy sequence number".  This
 * number keeps tracks of policy revisions and is used to detect if
 * one semanage client has committed policy changes while another is
 * still connected.
 */

#endif
