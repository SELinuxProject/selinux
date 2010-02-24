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
	 * A negative number is returned in case of failre */
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
	int (*install) (struct semanage_handle *, char *, size_t);

	/* Install a policy module */
	int (*install_file) (struct semanage_handle *, const char *);

	/* Upgrade a policy module */
	int (*upgrade) (struct semanage_handle *, char *, size_t);
	
	/* Upgrade a policy module */
	int (*upgrade_file) (struct semanage_handle *, const char *);

	/* Enable a policy module */
	int (*enable) (struct semanage_handle *, char *);

	/* Disable a policy module */
	int (*disable) (struct semanage_handle *, char *);

	/* Remove a policy module */
	int (*remove) (struct semanage_handle *, char *);

	/* List policy modules */
	int (*list) (struct semanage_handle *, semanage_module_info_t **,
		     int *);

	/* Install base policy */
	int (*install_base) (struct semanage_handle *, char *, size_t);

	/* Install a base module */
	int (*install_base_file) (struct semanage_handle *, const char *);
};

/* Should be backend independent */
extern int semanage_base_merge_components(struct semanage_handle *handle);

extern int semanage_commit_components(struct semanage_handle *handle);

#endif
