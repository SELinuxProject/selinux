#ifndef _SEMANAGE_BOOLEAN_INTERNAL_H_
#define _SEMANAGE_BOOLEAN_INTERNAL_H_

#include <semanage/boolean_record.h>
#include <semanage/booleans_local.h>
#include <semanage/booleans_policy.h>
#include <semanage/booleans_active.h>
#include "database.h"
#include "handle.h"

/* BOOL RECORD: method table */
extern const record_table_t SEMANAGE_BOOL_RTABLE;

extern int bool_file_dbase_init(semanage_handle_t * handle,
				const char *path_ro,
				const char *path_rw,
				dbase_config_t * dconfig);

extern void bool_file_dbase_release(dbase_config_t * dconfig);

extern int bool_policydb_dbase_init(semanage_handle_t * handle,
				    dbase_config_t * dconfig);

extern void bool_policydb_dbase_release(dbase_config_t * dconfig);

extern int bool_activedb_dbase_init(semanage_handle_t * handle,
				    dbase_config_t * dconfig);

extern void bool_activedb_dbase_release(dbase_config_t * dconfig);

#endif
