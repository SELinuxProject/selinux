#ifndef _SEMANAGE_PORT_INTERNAL_H_
#define _SEMANAGE_PORT_INTERNAL_H_

#include <semanage/port_record.h>
#include <semanage/ports_local.h>
#include <semanage/ports_policy.h>
#include "database.h"
#include "handle.h"
#include "dso.h"

hidden_proto(semanage_port_create)
    hidden_proto(semanage_port_compare)
    hidden_proto(semanage_port_compare2)
    hidden_proto(semanage_port_clone)
    hidden_proto(semanage_port_free)
    hidden_proto(semanage_port_key_extract)
    hidden_proto(semanage_port_key_free)
    hidden_proto(semanage_port_get_high)
    hidden_proto(semanage_port_get_low)
    hidden_proto(semanage_port_set_port)
    hidden_proto(semanage_port_set_range)
    hidden_proto(semanage_port_get_proto)
    hidden_proto(semanage_port_set_proto)
    hidden_proto(semanage_port_get_proto_str)
    hidden_proto(semanage_port_get_con)
    hidden_proto(semanage_port_set_con)
    hidden_proto(semanage_port_list_local)

/* PORT RECORD: method table */
extern record_table_t SEMANAGE_PORT_RTABLE;

extern int port_file_dbase_init(semanage_handle_t * handle,
				const char *path_ro,
				const char *path_rw,
				dbase_config_t * dconfig);

extern void port_file_dbase_release(dbase_config_t * dconfig);

extern int port_policydb_dbase_init(semanage_handle_t * handle,
				    dbase_config_t * dconfig);

extern void port_policydb_dbase_release(dbase_config_t * dconfig);

extern int hidden semanage_port_validate_local(semanage_handle_t * handle);

/* ==== Internal (to ports) API === */

hidden int semanage_port_compare2_qsort(const semanage_port_t ** port,
					const semanage_port_t ** port2);

#endif
