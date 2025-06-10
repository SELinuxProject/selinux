#ifndef _SEMANAGE_IBENDPORT_INTERNAL_H_
#define _SEMANAGE_IBENDPORT_INTERNAL_H_

#include <semanage/ibendport_record.h>
#include <semanage/ibendports_local.h>
#include <semanage/ibendports_policy.h>
#include "database.h"
#include "handle.h"

/* IBENDPORT RECORD: method table */
extern const record_table_t SEMANAGE_IBENDPORT_RTABLE;

extern int ibendport_file_dbase_init(semanage_handle_t *handle,
				     const char *path_ro,
				     const char *path_rw,
				     dbase_config_t *dconfig);

extern void ibendport_file_dbase_release(dbase_config_t *dconfig);

extern int ibendport_policydb_dbase_init(semanage_handle_t *handle,
					 dbase_config_t *dconfig);

extern void ibendport_policydb_dbase_release(dbase_config_t *dconfig);

extern int semanage_ibendport_validate_local(semanage_handle_t *handle);

/* ==== Internal (to ibendports) API === */

 int semanage_ibendport_compare2_qsort(const void *p1, const void *p2);

#endif
