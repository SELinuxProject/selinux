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

#ifndef _SEMANAGE_DATABASE_POLICYDB_INTERNAL_H_
#define _SEMANAGE_DATABASE_POLICYDB_INTERNAL_H_

#include <sepol/handle.h>
#include <sepol/policydb.h>
#include "database.h"
#include "handle.h"

struct dbase_policydb;
typedef struct dbase_policydb dbase_policydb_t;

typedef int (*record_policydb_table_add_t) (sepol_handle_t * h,
					    sepol_policydb_t * p,
					    const record_key_t * rkey,
					    const record_t * record);

typedef int (*record_policydb_table_modify_t) (sepol_handle_t * h,
					       sepol_policydb_t * p,
					       const record_key_t * rkey,
					       const record_t * record);

typedef int (*record_policydb_table_set_t) (sepol_handle_t * h,
					    sepol_policydb_t * p,
					    const record_key_t * rkey,
					    const record_t * record);

typedef int (*record_policydb_table_query_t) (sepol_handle_t * h,
					      const sepol_policydb_t * p,
					      const record_key_t * rkey,
					      record_t ** response);

typedef int (*record_policydb_table_count_t) (sepol_handle_t * h,
					      const sepol_policydb_t * p,
					      unsigned int *response);

typedef int (*record_policydb_table_exists_t) (sepol_handle_t * h,
					       const sepol_policydb_t * p,
					       const record_key_t * rkey,
					       int *response);

typedef int (*record_policydb_table_iterate_t) (sepol_handle_t * h,
						const sepol_policydb_t * p,
						int (*fn) (const record_t * r,
							   void *fn_arg),
						void *arg);

/* POLICYDB extension to RECORD interface - method table */
typedef struct record_policydb_table {
	/* Add policy record */
	record_policydb_table_add_t add;
	/* Modify policy record, or add if 
	 * the key isn't found */
	record_policydb_table_modify_t modify;
	/* Set policy record */
	record_policydb_table_set_t set;
	/* Query policy record  - return the record
	 * or NULL if it isn't found */
	record_policydb_table_query_t query;
	/* Count records */
	record_policydb_table_count_t count;
	/* Check if a record exists */
	record_policydb_table_exists_t exists;
	/* Iterate over records */
	record_policydb_table_iterate_t iterate;
} record_policydb_table_t;

/* Initialize database */
extern int dbase_policydb_init(semanage_handle_t * handle,
			       const char *path_ro,
			       const char *path_rw,
			       record_table_t * rtable,
			       record_policydb_table_t * rptable,
			       dbase_policydb_t ** dbase);

/* Attach to a shared policydb.
 * This implies drop_cache().
 * and prevents flush() and drop_cache()
 * until detached. */
extern void dbase_policydb_attach(dbase_policydb_t * dbase,
				  sepol_policydb_t * policydb);

/* Detach from a shared policdb.
 * This implies drop_cache. */
extern void dbase_policydb_detach(dbase_policydb_t * dbase);

/* Release allocated resources */
extern void dbase_policydb_release(dbase_policydb_t * dbase);

/* POLICYDB database - method table implementation */
extern dbase_table_t SEMANAGE_POLICYDB_DTABLE;

#endif
