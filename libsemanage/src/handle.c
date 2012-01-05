/* Author: Joshua Brindle <jbrindle@tresys.co
 *	   Jason Tang	  <jtang@tresys.com>
 *
 * Copyright (C) 2004-2005 Tresys Technology, LLC
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

/* This file implements only the publicly-visible handle functions to libsemanage. */

#include <selinux/selinux.h>

#include <stdarg.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "direct_api.h"
#include "handle.h"
#include "debug.h"
#include "semanage_conf.h"
#include "semanage_store.h"

#define SEMANAGE_COMMIT_READ_WAIT 5
#define SEMANAGE_CONF_PATH "/etc/selinux/semanage.conf"

#include <string.h>
#include <selinux/selinux.h>
static char *private_selinux_path = NULL;
static char *private_semanage_conf_path = NULL;
static char *private_file_context_path = NULL;
static char *private_file_context_local_path = NULL;
static char *private_file_context_homedir_path = NULL;
static char *private_homedir_context_path = NULL;
static char *private_binary_policy_path = NULL;
static char *private_usersconf_path = NULL;
static char *private_netfilter_context_path = NULL;
static char *private_policy_root = NULL;

void semanage_free_root() {
	free(private_selinux_path); private_selinux_path = NULL;
	free(private_semanage_conf_path); private_semanage_conf_path = NULL;
	free(private_file_context_path); private_file_context_path = NULL;
	free(private_file_context_local_path); private_file_context_local_path = NULL;
	free(private_file_context_homedir_path); private_file_context_homedir_path = NULL;
	free(private_homedir_context_path); private_homedir_context_path = NULL;
	free(private_binary_policy_path); private_binary_policy_path = NULL;
	free(private_usersconf_path); private_usersconf_path = NULL;
	free(private_netfilter_context_path); private_netfilter_context_path = NULL;
	free(private_policy_root); private_policy_root = NULL;
}

int semanage_set_root(const char *path) {
	semanage_free_root();
	if ( asprintf(&private_selinux_path, "%s/%s", path, selinux_path()) < 0 ) {
		goto error;
	}

	if ( asprintf(&private_semanage_conf_path, "%s/%s", path, SEMANAGE_CONF_PATH) < 0 ) {
		goto error;
	}

	if ( asprintf(&private_file_context_path, "%s/%s", path, selinux_file_context_path()) < 0 ) {
		goto error;
	}

	if ( asprintf(&private_file_context_local_path, "%s/%s", path, selinux_file_context_local_path()) < 0 ) {
		goto error;
	}

	if ( asprintf(&private_homedir_context_path, "%s/%s", path, selinux_homedir_context_path()) < 0 ) {
		goto error;
	}

	if ( asprintf(&private_file_context_homedir_path, "%s/%s", path, selinux_file_context_homedir_path()) < 0 ) {
		goto error;
	}

	if ( asprintf(&private_binary_policy_path, "%s/%s", path, selinux_binary_policy_path()) < 0 ) {
		goto error;
	}

	if ( asprintf(&private_usersconf_path, "%s/%s", path, selinux_usersconf_path()) < 0 ) {
		goto error;
	}

	if ( asprintf(&private_netfilter_context_path, "%s/%s", path, selinux_netfilter_context_path()) < 0 ) {
		goto error;
	}

	if ( asprintf(&private_policy_root, "%s/%s", path, selinux_policy_root()) < 0 ) {
		goto error;
	}

	return 0;
error:
	semanage_free_root();
	return -1;
}
hidden_def(semanage_set_root)

const char *semanage_file_context_path() {
//	printf("private_file_context_path %s\n", private_file_context_path);
	if (private_file_context_path)
		return private_file_context_path;
	return selinux_file_context_path();
}

const char *semanage_file_context_local_path() {
//	printf("private_file_context_local_path %s\n", private_file_context_local_path);
	if (private_file_context_local_path)
		return private_file_context_local_path;
	return selinux_file_context_local_path();
}

const char *semanage_file_context_homedir_path() {
//	printf("private_file_context_homedir_path %s\n", private_file_context_homedir_path);
	if (private_file_context_homedir_path)
		return private_file_context_homedir_path;

	return selinux_file_context_homedir_path();
}

const char *semanage_homedir_context_path() {
//	printf("private_homedir_context_path %s\n", private_homedir_context_path);
	if (private_homedir_context_path)
		return private_homedir_context_path;
	return selinux_homedir_context_path();
}

const char *semanage_binary_policy_path() {
//	printf("private_binary_policy_path %s\n", private_binary_policy_path);
	if (private_binary_policy_path)
		return private_binary_policy_path;
	return selinux_binary_policy_path();
}

const char *semanage_usersconf_path() {
//	printf("private_usersconf_path %s\n", private_usersconf_path);
	if (private_usersconf_path)
		return private_usersconf_path;
	return selinux_usersconf_path();
}

const char *semanage_netfilter_context_path() {
//	printf("private_netfilter_context_path %s\n", private_netfilter_context_path);
	if (private_netfilter_context_path)
		return private_netfilter_context_path;
	return selinux_netfilter_context_path();
}

const char *semanage_policy_root() {
//	printf("private_policy_root %s\n", private_policy_root);
	if (private_policy_root)
		return private_policy_root;
	return selinux_policy_root();
}

const char *semanage_selinux_path(void) {
//	printf("private_selinux_path %s\n", private_selinux_path);
	if (private_selinux_path)
		return private_selinux_path;
	return selinux_path();
}

/* Return a fully-qualified path + filename to the semanage
 * configuration file.  The caller must not alter the string returned
 * (and hence why this function return type is const).
 *
 */

const char *semanage_conf_path(void)
{
	if (private_semanage_conf_path &&
	    access(private_semanage_conf_path, R_OK) == 0)
		return private_semanage_conf_path;

	return SEMANAGE_CONF_PATH;
}

semanage_handle_t *semanage_handle_create(void)
{
	semanage_handle_t *sh = NULL;
	const char *conf_name = NULL;

	/* Allocate handle */
	if ((sh = calloc(1, sizeof(semanage_handle_t))) == NULL)
		goto err;

	if ((conf_name = semanage_conf_path()) == NULL)
		goto err;

	if ((sh->conf = semanage_conf_parse(conf_name)) == NULL)
		goto err;

	/* Link to sepol handle */
	sh->sepolh = sepol_handle_create();
	if (!sh->sepolh)
		goto err;
	sepol_msg_set_callback(sh->sepolh, semanage_msg_relay_handler, sh);

	/* By default do not rebuild the policy on commit
	 * If any changes are made, this flag is ignored */
	sh->do_rebuild = 0;

	/* By default always reload policy after commit if SELinux is enabled. */
	sh->do_reload = (is_selinux_enabled() > 0);

	/* By default always check the file contexts file. */
	sh->do_check_contexts = 1;

	/* By default do not create store */
	sh->create_store = 0;

	/* Set timeout: some default value for now, later use config */
	sh->timeout = SEMANAGE_COMMIT_READ_WAIT;

	/* Set callback */
	sh->msg_callback = semanage_msg_default_handler;
	sh->msg_callback_arg = NULL;

	return sh;

      err:
	semanage_handle_destroy(sh);
	return NULL;
}

void semanage_set_rebuild(semanage_handle_t * sh, int do_rebuild)
{

	assert(sh != NULL);

	sh->do_rebuild = do_rebuild;
	return;
}

void semanage_set_reload(semanage_handle_t * sh, int do_reload)
{

	assert(sh != NULL);

	sh->do_reload = do_reload;
	return;
}

void semanage_set_create_store(semanage_handle_t * sh, int create_store)
{

	assert(sh != NULL);

	sh->create_store = create_store;
	return;
}

int semanage_get_disable_dontaudit(semanage_handle_t * sh)
{
	assert(sh != NULL);

	return sepol_get_disable_dontaudit(sh->sepolh);
}

void semanage_set_disable_dontaudit(semanage_handle_t * sh, int disable_dontaudit)
{
	assert(sh != NULL);
	
	sepol_set_disable_dontaudit(sh->sepolh, disable_dontaudit);
	return;
}

int semanage_get_preserve_tunables(semanage_handle_t * sh)
{
	assert(sh != NULL);
	return sepol_get_preserve_tunables(sh->sepolh);
}

void semanage_set_preserve_tunables(semanage_handle_t * sh,
				    int preserve_tunables)
{
	assert(sh != NULL);
	sepol_set_preserve_tunables(sh->sepolh, preserve_tunables);
}

void semanage_set_check_contexts(semanage_handle_t * sh, int do_check_contexts)
{

	assert(sh != NULL);

	sh->do_check_contexts = do_check_contexts;
	return;
}

int semanage_is_connected(semanage_handle_t * sh)
{
	assert(sh != NULL);
	return sh->is_connected;
}

void semanage_select_store(semanage_handle_t * sh, char *storename,
			   enum semanage_connect_type storetype)
{

	assert(sh != NULL);

	/* This just sets the storename to what the user requests, no 
	   verification of existance will be done until connect */
	sh->conf->store_path = strdup(storename);
	assert(sh->conf->store_path); /* no way to return failure */
	sh->conf->store_type = storetype;

	return;
}

int semanage_is_managed(semanage_handle_t * sh)
{
	assert(sh != NULL);
	if (sh->is_connected) {
		ERR(sh, "Already connected.");
		return -1;
	}
	switch (sh->conf->store_type) {
	case SEMANAGE_CON_DIRECT:
		return semanage_direct_is_managed(sh);
	default:
		ERR(sh,
		    "The connection type specified within your semanage.conf file has not been implemented yet.");
		/* fall through */
	}
	return -1;
}

int semanage_mls_enabled(semanage_handle_t * sh)
{
	assert(sh != NULL);
	switch (sh->conf->store_type) {
	case SEMANAGE_CON_DIRECT:
		return semanage_direct_mls_enabled(sh);
	default:
		ERR(sh,
		    "The connection type specified within your semanage.conf file has not been implemented yet.");
		/* fall through */
	}
	return -1;
}

int semanage_connect(semanage_handle_t * sh)
{
	assert(sh != NULL);
	switch (sh->conf->store_type) {
	case SEMANAGE_CON_DIRECT:{
			if (semanage_direct_connect(sh) < 0) {
				return -1;
			}
			break;
		}
	default:{
			ERR(sh,
			    "The connection type specified within your semanage.conf file has not been implemented yet.");
			return -1;
		}
	}
	sh->is_connected = 1;
	return 0;
}

int semanage_access_check(semanage_handle_t * sh)
{
	assert(sh != NULL);
	switch (sh->conf->store_type) {
	case SEMANAGE_CON_DIRECT:
		return semanage_direct_access_check(sh);
	default:
		return -1;
	}

	return -1;		/* unreachable */
}

hidden_def(semanage_access_check)

int semanage_disconnect(semanage_handle_t * sh)
{
	assert(sh != NULL && sh->funcs != NULL
	       && sh->funcs->disconnect != NULL);
	if (!sh->is_connected) {
		return 0;
	}
	if (sh->funcs->disconnect(sh) < 0) {
		return -1;
	}
	sh->is_in_transaction = 0;
	sh->is_connected = 0;
	sh->modules_modified = 0;
	return 0;
}

void semanage_handle_destroy(semanage_handle_t * sh)
{
	if (sh == NULL)
		return;

	if (sh->funcs != NULL && sh->funcs->destroy != NULL)
		sh->funcs->destroy(sh);
	semanage_conf_destroy(sh->conf);
	sepol_handle_destroy(sh->sepolh);
	free(sh);
}

hidden_def(semanage_handle_destroy)

/********************* public transaction functions *********************/
int semanage_begin_transaction(semanage_handle_t * sh)
{
	assert(sh != NULL && sh->funcs != NULL
	       && sh->funcs->begin_trans != NULL);
	if (!sh->is_connected) {
		ERR(sh, "Not connected.");
		return -1;
	}
	if (sh->is_in_transaction) {
		return 0;
	}

	if (sh->funcs->begin_trans(sh) < 0) {
		return -1;
	}
	sh->is_in_transaction = 1;
	return 0;
}

hidden_def(semanage_begin_transaction)

int semanage_commit(semanage_handle_t * sh)
{
	int retval;
	assert(sh != NULL && sh->funcs != NULL && sh->funcs->commit != NULL);
	if (!sh->is_in_transaction) {
		ERR(sh,
		    "Will not commit because caller does not have a transaction lock yet.");
		return -1;
	}
	retval = sh->funcs->commit(sh);
	sh->is_in_transaction = 0;
	sh->modules_modified = 0;
	return retval;
}
