/* Copyright (C) 2005 Red Hat, Inc. */

#ifndef _SEMANAGE_DATABASE_ACTIVEDB_INTERNAL_H_
#define _SEMANAGE_DATABASE_ACTIVEDB_INTERNAL_H_

#include "database.h"
#include "handle.h"

struct dbase_activedb;
typedef struct dbase_activedb dbase_activedb_t;

/* ACTIVEDB extension to RECORD interface - method table */
typedef struct record_activedb_table {

	/* Read a list of records */
	int (*read_list) (semanage_handle_t * handle,
			  record_t *** records, unsigned int *count);

	/* Commit a list of records */
	int (*commit_list) (semanage_handle_t * handle,
			    record_t ** records, unsigned int count);

} record_activedb_table_t;

/* ACTIVEDB - initialization */
extern int dbase_activedb_init(semanage_handle_t * handle,
			       record_table_t * rtable,
			       record_activedb_table_t * ratable,
			       dbase_activedb_t ** dbase);

/* ACTIVEDB - release */
extern void dbase_activedb_release(dbase_activedb_t * dbase);

/* ACTIVEDB - method table implementation */
extern dbase_table_t SEMANAGE_ACTIVEDB_DTABLE;

#endif
