/*
 * Copyright (C) 2017 Mellanox Technologies Inc
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
 */

struct semanage_ibendport;
struct semanage_ibendport_key;
typedef struct semanage_ibendport record_t;
typedef struct semanage_ibendport_key record_key_t;
#define DBASE_RECORD_DEFINED

struct dbase_policydb;
typedef struct dbase_policydb dbase_t;
#define DBASE_DEFINED

#include <sepol/ibendports.h>
#include <semanage/handle.h>
#include "ibendport_internal.h"
#include "debug.h"
#include "database_policydb.h"
#include "semanage_store.h"

/* IBENDPORT RECORD (SEPOL): POLICYDB extension : method table */
static const record_policydb_table_t SEMANAGE_IBENDPORT_POLICYDB_RTABLE = {
	.add = NULL,
	.modify = (record_policydb_table_modify_t)sepol_ibendport_modify,
	.set = NULL,
	.query = (record_policydb_table_query_t)sepol_ibendport_query,
	.count = (record_policydb_table_count_t)sepol_ibendport_count,
	.exists = (record_policydb_table_exists_t)sepol_ibendport_exists,
	.iterate = (record_policydb_table_iterate_t)sepol_ibendport_iterate,
};

int ibendport_policydb_dbase_init(semanage_handle_t *handle,
				  dbase_config_t *dconfig)
{
	if (dbase_policydb_init(handle,
				semanage_path(SEMANAGE_ACTIVE, SEMANAGE_STORE_KERNEL),
				semanage_path(SEMANAGE_TMP, SEMANAGE_STORE_KERNEL),
				&SEMANAGE_IBENDPORT_RTABLE,
				&SEMANAGE_IBENDPORT_POLICYDB_RTABLE,
				&dconfig->dbase) < 0)
		return STATUS_ERR;

	dconfig->dtable = &SEMANAGE_POLICYDB_DTABLE;

	return STATUS_SUCCESS;
}

void ibendport_policydb_dbase_release(dbase_config_t *dconfig)
{
	dbase_policydb_release(dconfig->dbase);
}
