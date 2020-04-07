#ifndef _SEMANAGE_IFACE_INTERNAL_H_
#define _SEMANAGE_IFACE_INTERNAL_H_

#include <semanage/iface_record.h>
#include <semanage/interfaces_local.h>
#include <semanage/interfaces_policy.h>
#include "database.h"
#include "handle.h"

/* IFACE RECORD: method table */
extern record_table_t SEMANAGE_IFACE_RTABLE;

extern int iface_policydb_dbase_init(semanage_handle_t * handle,
				     dbase_config_t * dconfig);

extern void iface_policydb_dbase_release(dbase_config_t * dconfig);

extern int iface_file_dbase_init(semanage_handle_t * handle,
				 const char *path_ro,
				 const char *path_rw,
				 dbase_config_t * dconfig);

extern void iface_file_dbase_release(dbase_config_t * dconfig);

#endif
