#ifndef _SEMANAGE_NODE_INTERNAL_H_
#define _SEMANAGE_NODE_INTERNAL_H_

#include <semanage/node_record.h>
#include <semanage/nodes_local.h>
#include <semanage/nodes_policy.h>
#include "database.h"
#include "handle.h"

/* NODE RECORD: method table */
extern record_table_t SEMANAGE_NODE_RTABLE;

extern int node_file_dbase_init(semanage_handle_t * handle,
				const char *path_ro,
				const char *path_rw,
				dbase_config_t * dconfig);

extern void node_file_dbase_release(dbase_config_t * dconfig);

extern int node_policydb_dbase_init(semanage_handle_t * handle,
				    dbase_config_t * dconfig);

extern void node_policydb_dbase_release(dbase_config_t * dconfig);

extern int semanage_node_validate_local(semanage_handle_t * handle);

/* ==== Internal (to nodes) API === */

 int semanage_node_compare2_qsort(const semanage_node_t ** node,
					const semanage_node_t ** node2);

#endif
