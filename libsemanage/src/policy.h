/* Author: Joshua Brindle <jbrindle@tresys.com>
 *         Jason Tang     <jtang@tresys.com>
 *
 * Copyright (C) 2005 Tresys Technology, LLC
 * Copyright (C) 2005 Red Hat Inc.
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

#ifndef _SEMANAGE_POLICY_INTERNAL_H_
#define _SEMANAGE_POLICY_INTERNAL_H_

#include "modules.h"

/* Circular dependency */
struct semanage_handle;

/* Backend dependent portion */
struct semanage_policy_table {

	/* Returns the current policy serial/commit number
	 * A negative number is returned in case of failure */
	int (*get_serial) (struct semanage_handle *);

	/* Destroy a connection */
	void (*destroy) (struct semanage_handle *);

	/* Disconnect from policy */
	int (*disconnect) (struct semanage_handle *);

	/* Begin a policy transaction */
	int (*begin_trans) (struct semanage_handle *);

	/* Commit a policy transaction */
	int (*commit) (struct semanage_handle *);

	/* Install a policy module */
	int (*install) (struct semanage_handle *, char *, size_t, const char *, const char *);

	/* Install a policy module */
	int (*install_file) (struct semanage_handle *, const char *);

	/* Extract a policy module */
	int (*extract) (struct semanage_handle *,
				 semanage_module_key_t *,
				 int extract_cil,
				 void **,
				 size_t *,
				 semanage_module_info_t **);

	/* Remove a policy module */
	int (*remove) (struct semanage_handle *, char *);

	/* List policy modules */
	int (*list) (struct semanage_handle *, semanage_module_info_t **,
		     int *);

	/* Get module enabled status */
	int (*get_enabled) (struct semanage_handle *sh,
			    const semanage_module_key_t *key,
			    int *enabled);

	/* Set module enabled status */
	int (*set_enabled) (struct semanage_handle *sh,
			    const semanage_module_key_t *key,
			    int enabled);

	/* Get a module info */
	int (*get_module_info) (struct semanage_handle *,
				const semanage_module_key_t *,
				semanage_module_info_t **);

	/* List all policy modules */
	int (*list_all) (struct semanage_handle *,
			 semanage_module_info_t **,
			 int *);

	/* Install via module info */
	int (*install_info) (struct semanage_handle *,
			     const semanage_module_info_t *,
			     char *,
			     size_t);

	/* Remove via module key */
	int (*remove_key) (struct semanage_handle *,
			   const semanage_module_key_t *);
};

/* Should be backend independent */
extern int semanage_base_merge_components(struct semanage_handle *handle);

extern int semanage_commit_components(struct semanage_handle *handle);

#endif
