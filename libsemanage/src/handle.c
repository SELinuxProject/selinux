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

#include <ctype.h>
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

static char *private_semanage_root = NULL;

int semanage_set_root(const char *root)
{
	free(private_semanage_root);
	private_semanage_root = strdup(root);
	return 0;
}


const char * semanage_root(void)
{
	if (private_semanage_root == NULL) {
		return "";
	}
	return private_semanage_root;
}


semanage_handle_t *semanage_handle_create(void)
{
	semanage_handle_t *sh = NULL;
	char *conf_name = NULL;

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

	/* Default priority is 400 */
	sh->priority = 400;

	/* By default do not rebuild the policy on commit
	 * If any changes are made, this flag is ignored */
	sh->do_rebuild = 0;

	sh->commit_err = 0;

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

	free(conf_name);

	return sh;

      err:
	free(conf_name);
	semanage_handle_destroy(sh);
	return NULL;
}

void semanage_set_rebuild(semanage_handle_t * sh, int do_rebuild)
{
	assert(sh != NULL);

	sh->do_rebuild = do_rebuild;
}

void semanage_set_reload(semanage_handle_t * sh, int do_reload)
{
	assert(sh != NULL);

	sh->do_reload = do_reload;
}

void semanage_set_check_ext_changes(semanage_handle_t * sh, int do_check)
{
	assert(sh != NULL);

	sh->check_ext_changes = do_check;
}

int semanage_get_hll_compiler_path(semanage_handle_t *sh,
				char *lang_ext,
				char **compiler_path)
{
	assert(sh != NULL);
	assert(lang_ext != NULL);

	int i;
	int status = 0;
	int num_printed = 0;
	size_t len;
	char *compiler = NULL;
	char *lower_lang_ext = NULL;

	lower_lang_ext = strdup(lang_ext);
	if (lower_lang_ext == NULL) {
		ERR(sh, "Could not create copy of lang_ext. Out of memory.\n");
		status = -1;
		goto cleanup;
	}
	/* Set lang_ext to lowercase in case a file with a mixed case extension was passed to libsemanage */
	for (i = 0; lower_lang_ext[i] != '\0'; i++) {
		lower_lang_ext[i] = tolower(lower_lang_ext[i]);
	}

	len = strlen(sh->conf->compiler_directory_path) + strlen("/") + strlen(lower_lang_ext) + 1;

	compiler = malloc(len * sizeof(*compiler));
	if (compiler == NULL) {
		ERR(sh, "Error allocating space for compiler path.");
		status = -1;
		goto cleanup;
	}

	num_printed = snprintf(compiler, len, "%s/%s", sh->conf->compiler_directory_path, lower_lang_ext);
	if (num_printed < 0 || (int)num_printed >= (int)len) {
		ERR(sh, "Error creating compiler path.");
		status = -1;
		goto cleanup;
	}

	*compiler_path = compiler;
	status = 0;

cleanup:
	free(lower_lang_ext);
	if (status != 0) {
		free(compiler);
	}

	return status;
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

int semanage_get_ignore_module_cache(semanage_handle_t *sh)
{
	assert(sh != NULL);
	return sh->conf->ignore_module_cache;
}

void semanage_set_ignore_module_cache(semanage_handle_t *sh,
				    int ignore_module_cache)
{
	assert(sh != NULL);
	sh->conf->ignore_module_cache = ignore_module_cache;
}

void semanage_set_check_contexts(semanage_handle_t * sh, int do_check_contexts)
{

	assert(sh != NULL);

	sh->do_check_contexts = do_check_contexts;
	return;
}

uint16_t semanage_get_default_priority(semanage_handle_t *sh)
{
	assert(sh != NULL);
	return sh->priority;
}

int semanage_set_default_priority(semanage_handle_t *sh, uint16_t priority)
{
	assert(sh != NULL);

	/* Verify priority */
	if (semanage_module_validate_priority(priority) < 0) {
		ERR(sh, "Priority %d is invalid.", priority);
		return -1;
	}

	sh->priority = priority;
	return 0;
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
	   verification of existence will be done until connect */
	free(sh->conf->store_path);
	sh->conf->store_path = strdup(storename);
	assert(sh->conf->store_path); /* no way to return failure */
	sh->conf->store_type = storetype;

	return;
}

void semanage_set_store_root(semanage_handle_t *sh, const char *store_root)
{
	assert(sh != NULL);

	free(sh->conf->store_root_path);
	sh->conf->store_root_path = strdup(store_root);
	assert(sh->conf->store_root_path); /* no way to return failure */

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
