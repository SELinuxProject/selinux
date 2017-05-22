#ifndef _SEMANAGE_IBPKEY_INTERNAL_H_
#define _SEMANAGE_IBPKEY_INTERNAL_H_

#include <semanage/ibpkey_record.h>
#include <semanage/ibpkeys_local.h>
#include <semanage/ibpkeys_policy.h>
#include "database.h"
#include "handle.h"
#include "dso.h"

hidden_proto(semanage_ibpkey_create)
hidden_proto(semanage_ibpkey_compare)
hidden_proto(semanage_ibpkey_compare2)
hidden_proto(semanage_ibpkey_clone)
hidden_proto(semanage_ibpkey_free)
hidden_proto(semanage_ibpkey_key_extract)
hidden_proto(semanage_ibpkey_key_free)
hidden_proto(semanage_ibpkey_get_high)
hidden_proto(semanage_ibpkey_get_low)
hidden_proto(semanage_ibpkey_set_pkey)
hidden_proto(semanage_ibpkey_set_range)
hidden_proto(semanage_ibpkey_get_con)
hidden_proto(semanage_ibpkey_set_con)
hidden_proto(semanage_ibpkey_list_local)
hidden_proto(semanage_ibpkey_get_subnet_prefix)
hidden_proto(semanage_ibpkey_get_subnet_prefix_bytes)
hidden_proto(semanage_ibpkey_set_subnet_prefix)
hidden_proto(semanage_ibpkey_set_subnet_prefix_bytes)

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

extern int hidden semanage_ibpkey_validate_local(semanage_handle_t *handle);

/* ==== Internal (to ibpkeys) API === */

hidden int semanage_ibpkey_compare2_qsort(const semanage_ibpkey_t **ibpkey,
					  const semanage_ibpkey_t **ibpkey2);

#endif
