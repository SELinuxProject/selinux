/* Copyright (C) 2005 Red Hat, Inc. */

#ifndef _SEMANAGE_DATABASE_JOIN_INTERNAL_H_
#define _SEMANAGE_DATABASE_JOIN_INTERNAL_H_

#include "database.h"
#include "handle.h"

#ifndef DBASE_RECORD_JOIN_DEFINED
typedef void *record1_t;
typedef void *record2_t;
#define DBASE_RECORD_JOIN_DEFINED
#endif

struct dbase_join;
typedef struct dbase_join dbase_join_t;

/* JOIN extension to RECORD interface - method table */
typedef struct record_join_table {

	/* Join two records together.
	 * One of the provided records could be NULL */
	int (*join) (semanage_handle_t * handle,
		     const record1_t * record1,
		     const record2_t * record2, record_t ** result);

	/* Splits a record into two */
	int (*split) (semanage_handle_t * handle,
		      const record_t * record,
		      record1_t ** split1, record2_t ** split2);

} record_join_table_t;

/* JOIN - initialization */
extern int dbase_join_init(semanage_handle_t * handle,
			   record_table_t * rtable,
			   record_join_table_t * rjtable,
			   dbase_config_t * join1,
			   dbase_config_t * join2, dbase_join_t ** dbase);

/* FILE - release */
extern void dbase_join_release(dbase_join_t * dbase);

/* JOIN - method table implementation */
extern dbase_table_t SEMANAGE_JOIN_DTABLE;

#endif
