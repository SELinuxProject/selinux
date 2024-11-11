#ifndef _SEMANAGE_PORT_INTERNAL_H_
#define _SEMANAGE_PORT_INTERNAL_H_

#include <semanage/port_record.h>
#include <semanage/ports_local.h>
#include <semanage/ports_policy.h>
#include "database.h"
#include "handle.h"

/* PORT RECORD: method table */
extern const record_table_t SEMANAGE_PORT_RTABLE;

extern int port_file_dbase_init(semanage_handle_t * handle,
				const char *path_ro,
				const char *path_rw,
				dbase_config_t * dconfig);

extern void port_file_dbase_release(dbase_config_t * dconfig);

extern int port_policydb_dbase_init(semanage_handle_t * handle,
				    dbase_config_t * dconfig);

extern void port_policydb_dbase_release(dbase_config_t * dconfig);

extern int semanage_port_validate_local(semanage_handle_t * handle);

/* ==== Internal (to ports) API === */

 int semanage_port_compare2_qsort(const void* p1, const void *p2);

#endif
