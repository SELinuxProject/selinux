#ifndef _SEMANAGE_SEUSER_INTERNAL_H_
#define _SEMANAGE_SEUSER_INTERNAL_H_

#include <semanage/seuser_record.h>
#include <semanage/seusers_local.h>
#include <semanage/seusers_policy.h>
#include <sepol/policydb.h>
#include "database.h"
#include "handle.h"
#include "dso.h"

hidden_proto(semanage_seuser_clone)
    hidden_proto(semanage_seuser_compare)
    hidden_proto(semanage_seuser_compare2)
    hidden_proto(semanage_seuser_create)
    hidden_proto(semanage_seuser_free)
    hidden_proto(semanage_seuser_get_mlsrange)
    hidden_proto(semanage_seuser_get_name)
    hidden_proto(semanage_seuser_get_sename)
    hidden_proto(semanage_seuser_key_create)
    hidden_proto(semanage_seuser_key_extract)
    hidden_proto(semanage_seuser_key_free)
    hidden_proto(semanage_seuser_set_mlsrange)
    hidden_proto(semanage_seuser_set_name)
    hidden_proto(semanage_seuser_set_sename)
    hidden_proto(semanage_seuser_iterate)
    hidden_proto(semanage_seuser_iterate_local)

/* SEUSER RECORD: method table */
extern record_table_t SEMANAGE_SEUSER_RTABLE;

extern int seuser_file_dbase_init(semanage_handle_t * handle,
				  const char *path_ro,
				  const char *path_rw,
				  dbase_config_t * dconfig);

extern void seuser_file_dbase_release(dbase_config_t * dconfig);

extern int hidden semanage_seuser_validate_local(semanage_handle_t * handle,
						 const sepol_policydb_t *
						 policydb);

#endif
