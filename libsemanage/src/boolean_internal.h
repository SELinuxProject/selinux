#ifndef _SEMANAGE_BOOLEAN_INTERNAL_H_
#define _SEMANAGE_BOOLEAN_INTERNAL_H_

#include <semanage/boolean_record.h>
#include <semanage/booleans_local.h>
#include <semanage/booleans_policy.h>
#include <semanage/booleans_active.h>
#include "database.h"
#include "handle.h"
#include "dso.h"

hidden_proto(semanage_bool_clone)
    hidden_proto(semanage_bool_compare)
    hidden_proto(semanage_bool_compare2)
    hidden_proto(semanage_bool_create)
    hidden_proto(semanage_bool_free)
    hidden_proto(semanage_bool_get_name)
    hidden_proto(semanage_bool_get_value)
    hidden_proto(semanage_bool_key_extract)
    hidden_proto(semanage_bool_key_free)
    hidden_proto(semanage_bool_set_name)
    hidden_proto(semanage_bool_set_value)

/* BOOL RECORD: metod table */
extern record_table_t SEMANAGE_BOOL_RTABLE;

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
