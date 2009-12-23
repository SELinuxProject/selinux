#ifndef _SEMANAGE_IFACE_INTERNAL_H_
#define _SEMANAGE_IFACE_INTERNAL_H_

#include <semanage/iface_record.h>
#include <semanage/interfaces_local.h>
#include <semanage/interfaces_policy.h>
#include "database.h"
#include "handle.h"
#include "dso.h"

hidden_proto(semanage_iface_create)
    hidden_proto(semanage_iface_compare)
    hidden_proto(semanage_iface_compare2)
    hidden_proto(semanage_iface_clone)
    hidden_proto(semanage_iface_free)
    hidden_proto(semanage_iface_get_ifcon)
    hidden_proto(semanage_iface_get_msgcon)
    hidden_proto(semanage_iface_get_name)
    hidden_proto(semanage_iface_key_extract)
    hidden_proto(semanage_iface_key_free)
    hidden_proto(semanage_iface_set_ifcon)
    hidden_proto(semanage_iface_set_msgcon)
    hidden_proto(semanage_iface_set_name)

/* IFACE RECORD: metod table */
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
