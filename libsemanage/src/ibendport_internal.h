#ifndef _SEMANAGE_IBENDPORT_INTERNAL_H_
#define _SEMANAGE_IBENDPORT_INTERNAL_H_

#include <semanage/ibendport_record.h>
#include <semanage/ibendports_local.h>
#include <semanage/ibendports_policy.h>
#include "database.h"
#include "handle.h"
#include "dso.h"

hidden_proto(semanage_ibendport_create)
hidden_proto(semanage_ibendport_compare)
hidden_proto(semanage_ibendport_compare2)
hidden_proto(semanage_ibendport_clone)
hidden_proto(semanage_ibendport_free)
hidden_proto(semanage_ibendport_key_extract)
hidden_proto(semanage_ibendport_key_free)
hidden_proto(semanage_ibendport_get_port)
hidden_proto(semanage_ibendport_set_port)
hidden_proto(semanage_ibendport_get_con)
hidden_proto(semanage_ibendport_set_con)
hidden_proto(semanage_ibendport_list_local)
hidden_proto(semanage_ibendport_get_ibdev_name)
hidden_proto(semanage_ibendport_set_ibdev_name)

/* IBENDPORT RECORD: method table */
extern record_table_t SEMANAGE_IBENDPORT_RTABLE;

extern int ibendport_file_dbase_init(semanage_handle_t *handle,
				     const char *path_ro,
				     const char *path_rw,
				     dbase_config_t *dconfig);

extern void ibendport_file_dbase_release(dbase_config_t *dconfig);

extern int ibendport_policydb_dbase_init(semanage_handle_t *handle,
					 dbase_config_t *dconfig);

extern void ibendport_policydb_dbase_release(dbase_config_t *dconfig);

extern int hidden semanage_ibendport_validate_local(semanage_handle_t *handle);

/* ==== Internal (to ibendports) API === */

hidden int semanage_ibendport_compare2_qsort(const semanage_ibendport_t **ibendport,
					     const semanage_ibendport_t **ibendport2);

#endif
