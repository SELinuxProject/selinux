#ifndef _SEMANAGE_SEUSER_INTERNAL_H_
#define _SEMANAGE_SEUSER_INTERNAL_H_

#include <semanage/seuser_record.h>
#include <semanage/seusers_local.h>
#include <semanage/seusers_policy.h>
#include <sepol/policydb.h>
#include "database.h"
#include "handle.h"

/* SEUSER RECORD: method table */
extern const record_table_t SEMANAGE_SEUSER_RTABLE;

extern int seuser_file_dbase_init(semanage_handle_t * handle,
				  const char *path_ro,
				  const char *path_rw,
				  dbase_config_t * dconfig);

extern void seuser_file_dbase_release(dbase_config_t * dconfig);

extern int semanage_seuser_validate_local(semanage_handle_t * handle,
						 const sepol_policydb_t *
						 policydb);

#endif
