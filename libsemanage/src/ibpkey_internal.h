#ifndef _SEMANAGE_IBPKEY_INTERNAL_H_
#define _SEMANAGE_IBPKEY_INTERNAL_H_

#include <semanage/ibpkey_record.h>
#include <semanage/ibpkeys_local.h>
#include <semanage/ibpkeys_policy.h>
#include "database.h"
#include "handle.h"

/* PKEY RECORD: method table */
extern record_table_t SEMANAGE_IBPKEY_RTABLE;

extern int ibpkey_file_dbase_init(semanage_handle_t *handle,
				  const char *path_ro,
				  const char *path_rw,
				  dbase_config_t *dconfig);

extern void ibpkey_file_dbase_release(dbase_config_t *dconfig);

extern int ibpkey_policydb_dbase_init(semanage_handle_t *handle,
				      dbase_config_t *dconfig);

extern void ibpkey_policydb_dbase_release(dbase_config_t *dconfig);

extern int semanage_ibpkey_validate_local(semanage_handle_t *handle);

/* ==== Internal (to ibpkeys) API === */

 int semanage_ibpkey_compare2_qsort(const semanage_ibpkey_t **ibpkey,
					  const semanage_ibpkey_t **ibpkey2);

#endif
