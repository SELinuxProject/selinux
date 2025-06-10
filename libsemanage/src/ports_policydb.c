/*
 * Copyright (C) 2006 Tresys Technology, LLC
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
/* Copyright (C) 2005 Red Hat, Inc. */

struct semanage_port;
struct semanage_port_key;
typedef struct semanage_port record_t;
typedef struct semanage_port_key record_key_t;
#define DBASE_RECORD_DEFINED

struct dbase_policydb;
typedef struct dbase_policydb dbase_t;
#define DBASE_DEFINED

#include <sepol/ports.h>
#include <semanage/handle.h>
#include "port_internal.h"
#include "debug.h"
#include "database_policydb.h"
#include "semanage_store.h"

/* PORT RECORD (SEPOL): POLICYDB extension : method table */
static const record_policydb_table_t SEMANAGE_PORT_POLICYDB_RTABLE = {
	.add = NULL,
	.modify = (record_policydb_table_modify_t) sepol_port_modify,
	.set = NULL,
	.query = (record_policydb_table_query_t) sepol_port_query,
	.count = (record_policydb_table_count_t) sepol_port_count,
	.exists = (record_policydb_table_exists_t) sepol_port_exists,
	.iterate = (record_policydb_table_iterate_t) sepol_port_iterate,
};

int port_policydb_dbase_init(semanage_handle_t * handle,
			     dbase_config_t * dconfig)
{

	if (dbase_policydb_init(handle,
				semanage_path(SEMANAGE_ACTIVE, SEMANAGE_STORE_KERNEL),
				semanage_path(SEMANAGE_TMP, SEMANAGE_STORE_KERNEL),
				&SEMANAGE_PORT_RTABLE,
				&SEMANAGE_PORT_POLICYDB_RTABLE,
				&dconfig->dbase) < 0)
		return STATUS_ERR;

	dconfig->dtable = &SEMANAGE_POLICYDB_DTABLE;

	return STATUS_SUCCESS;
}

void port_policydb_dbase_release(dbase_config_t * dconfig)
{

	dbase_policydb_release(dconfig->dbase);
}
