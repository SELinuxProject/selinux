/* Copyright (C) 2005 Red Hat, Inc. */

#ifndef _SEMANAGE_DATABASE_FILE_INTERNAL_H_
#define _SEMANAGE_DATABASE_FILE_INTERNAL_H_

#include <stdio.h>
#include "database.h"
#include "parse_utils.h"
#include "handle.h"

struct dbase_file;
typedef struct dbase_file dbase_file_t;

/* FILE extension to RECORD interface - method table */
typedef struct record_file_table {

	/* Fill record structuure based on supplied parse info.
	 * Parser must return STATUS_NODATA when EOF is encountered.
	 * Parser must handle NULL file stream correctly */
	int (*parse) (semanage_handle_t * handle,
		      parse_info_t * info, record_t * record);

	/* Print record to stream */
	int (*print) (semanage_handle_t * handle,
		      const record_t * record, FILE * str);

} record_file_table_t;

/* FILE - initialization */
extern int dbase_file_init(semanage_handle_t * handle,
			   const char *path_ro,
			   const char *path_rw,
			   const record_table_t * rtable,
			   const record_file_table_t * rftable,
			   dbase_file_t ** dbase);

/* FILE - release */
extern void dbase_file_release(dbase_file_t * dbase);

/* FILE - method table implementation */
extern const dbase_table_t SEMANAGE_FILE_DTABLE;

#endif
