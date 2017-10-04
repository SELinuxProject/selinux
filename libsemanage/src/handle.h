/* Author: Joshua Brindle <jbrindle@tresys.com>
 *         Jason Tang     <jtang@tresys.com>
 *         Ivan Gyurdiev  <ivg2@cornell.edu>
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

#ifndef _SEMANAGE_INTERNAL_HANDLE_H_
#define _SEMANAGE_INTERNAL_HANDLE_H_

#include <stdint.h>
#include <stddef.h>
#include "handle_internal.h"
#include <sepol/handle.h>
#include "modules.h"
#include "semanage_conf.h"
#include "database.h"
#include "direct_api.h"
#include "policy.h"

struct semanage_handle {
	int con_id;		/* Connection ID */

	/* Error handling */
	int msg_level;
	const char *msg_channel;
	const char *msg_fname;
#ifdef __GNUC__
	__attribute__ ((format(printf, 3, 4)))
#endif
	void (*msg_callback) (void *varg,
			      semanage_handle_t * handle, const char *fmt, ...);
	void *msg_callback_arg;

	/* Direct vs Server specific handle */
	union {
		struct semanage_direct_handle direct;
	} u;

	/* Libsepol handle */
	sepol_handle_t *sepolh;

	semanage_conf_t *conf;

	uint16_t priority;
	int is_connected;
	int is_in_transaction;
	int do_reload;		/* whether to reload policy after commit */
	int do_rebuild;		/* whether to rebuild policy if there were no changes */
	int modules_modified;
	int create_store;	/* whether to create the store if it does not exist
				 * this will only have an effect on direct connections */
	int do_check_contexts;	/* whether to run setfiles check the file contexts file */

	/* This timeout is used for transactions and waiting for lock
	   -1 means wait indefinetely
	   0 means return immediately
	   >0 means wait that many seconds */
	int timeout;

	/* these function pointers will point to the appropriate
	 * routine given the connection type.  think of these as
	 * simulating polymorphism for non-OO languages. */
	struct semanage_policy_table *funcs;

	/* Object databases */
#define DBASE_COUNT      24

/* Local modifications */
#define DBASE_LOCAL_USERS_BASE  0
#define DBASE_LOCAL_USERS_EXTRA 1
#define DBASE_LOCAL_USERS       2
#define DBASE_LOCAL_PORTS       3
#define DBASE_LOCAL_INTERFACES  4
#define DBASE_LOCAL_BOOLEANS    5
#define DBASE_LOCAL_FCONTEXTS	6
#define DBASE_LOCAL_SEUSERS     7
#define DBASE_LOCAL_NODES       8
#define DBASE_LOCAL_IBPKEYS     9
#define DBASE_LOCAL_IBENDPORTS  10

/* Policy + Local modifications */
#define DBASE_POLICY_USERS_BASE  11
#define DBASE_POLICY_USERS_EXTRA 12
#define DBASE_POLICY_USERS       13
#define DBASE_POLICY_PORTS       14
#define DBASE_POLICY_INTERFACES  15
#define DBASE_POLICY_BOOLEANS    16
#define DBASE_POLICY_FCONTEXTS   17
#define DBASE_POLICY_FCONTEXTS_H 18
#define DBASE_POLICY_SEUSERS     19
#define DBASE_POLICY_NODES       20
#define DBASE_POLICY_IBPKEYS     21
#define DBASE_POLICY_IBENDPORTS  22

/* Active kernel policy */
#define DBASE_ACTIVE_BOOLEANS    23
	dbase_config_t dbase[DBASE_COUNT];
};

/* === Local modifications === */
static inline
    dbase_config_t * semanage_user_base_dbase_local(semanage_handle_t * handle)
{
	return &handle->dbase[DBASE_LOCAL_USERS_BASE];
}

static inline
    dbase_config_t * semanage_user_extra_dbase_local(semanage_handle_t * handle)
{
	return &handle->dbase[DBASE_LOCAL_USERS_EXTRA];
}

static inline
    dbase_config_t * semanage_user_dbase_local(semanage_handle_t * handle)
{
	return &handle->dbase[DBASE_LOCAL_USERS];
}

static inline
    dbase_config_t * semanage_port_dbase_local(semanage_handle_t * handle)
{
	return &handle->dbase[DBASE_LOCAL_PORTS];
}

static inline
    dbase_config_t * semanage_ibpkey_dbase_local(semanage_handle_t * handle)
{
	return &handle->dbase[DBASE_LOCAL_IBPKEYS];
}

static inline
    dbase_config_t * semanage_ibendport_dbase_local(semanage_handle_t * handle)
{
	return &handle->dbase[DBASE_LOCAL_IBENDPORTS];
}

static inline
    dbase_config_t * semanage_iface_dbase_local(semanage_handle_t * handle)
{
	return &handle->dbase[DBASE_LOCAL_INTERFACES];
}

static inline
    dbase_config_t * semanage_bool_dbase_local(semanage_handle_t * handle)
{
	return &handle->dbase[DBASE_LOCAL_BOOLEANS];
}

static inline
    dbase_config_t * semanage_fcontext_dbase_local(semanage_handle_t * handle)
{
	return &handle->dbase[DBASE_LOCAL_FCONTEXTS];
}

static inline
    dbase_config_t * semanage_seuser_dbase_local(semanage_handle_t * handle)
{
	return &handle->dbase[DBASE_LOCAL_SEUSERS];
}

static inline
    dbase_config_t * semanage_node_dbase_local(semanage_handle_t * handle)
{
	return &handle->dbase[DBASE_LOCAL_NODES];
}

/* === Policy + Local modifications === */
static inline
    dbase_config_t * semanage_user_base_dbase_policy(semanage_handle_t * handle)
{
	return &handle->dbase[DBASE_POLICY_USERS_BASE];
}

static inline
    dbase_config_t * semanage_user_extra_dbase_policy(semanage_handle_t *
						      handle)
{
	return &handle->dbase[DBASE_POLICY_USERS_EXTRA];
}

static inline
    dbase_config_t * semanage_user_dbase_policy(semanage_handle_t * handle)
{
	return &handle->dbase[DBASE_POLICY_USERS];
}

static inline
    dbase_config_t * semanage_port_dbase_policy(semanage_handle_t * handle)
{
	return &handle->dbase[DBASE_POLICY_PORTS];
}

static inline
    dbase_config_t * semanage_ibpkey_dbase_policy(semanage_handle_t * handle)
{
	return &handle->dbase[DBASE_POLICY_IBPKEYS];
}

static inline
    dbase_config_t * semanage_ibendport_dbase_policy(semanage_handle_t * handle)
{
	return &handle->dbase[DBASE_POLICY_IBENDPORTS];
}

static inline
    dbase_config_t * semanage_iface_dbase_policy(semanage_handle_t * handle)
{
	return &handle->dbase[DBASE_POLICY_INTERFACES];
}

static inline
    dbase_config_t * semanage_bool_dbase_policy(semanage_handle_t * handle)
{
	return &handle->dbase[DBASE_POLICY_BOOLEANS];
}

static inline
    dbase_config_t * semanage_fcontext_dbase_policy(semanage_handle_t * handle)
{
	return &handle->dbase[DBASE_POLICY_FCONTEXTS];
}

static inline
    dbase_config_t * semanage_fcontext_dbase_homedirs(semanage_handle_t * handle)
{
	return &handle->dbase[DBASE_POLICY_FCONTEXTS_H];
}

static inline
    dbase_config_t * semanage_seuser_dbase_policy(semanage_handle_t * handle)
{
	return &handle->dbase[DBASE_POLICY_SEUSERS];
}

static inline
    dbase_config_t * semanage_node_dbase_policy(semanage_handle_t * handle)
{
	return &handle->dbase[DBASE_POLICY_NODES];
}

/* === Active kernel policy === */
static inline
    dbase_config_t * semanage_bool_dbase_active(semanage_handle_t * handle)
{
	return &handle->dbase[DBASE_ACTIVE_BOOLEANS];
}

#endif
