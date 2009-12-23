#ifndef _SEMANAGE_FCONTEXT_INTERNAL_H_
#define _SEMANAGE_FCONTEXT_INTERNAL_H_

#include <semanage/fcontext_record.h>
#include <semanage/fcontexts_local.h>
#include <semanage/fcontexts_policy.h>
#include <sepol/policydb.h>
#include "database.h"
#include "handle.h"
#include "dso.h"

hidden_proto(semanage_fcontext_key_create)
    hidden_proto(semanage_fcontext_key_extract)
    hidden_proto(semanage_fcontext_key_free)
    hidden_proto(semanage_fcontext_compare)
    hidden_proto(semanage_fcontext_compare2)
    hidden_proto(semanage_fcontext_create)
    hidden_proto(semanage_fcontext_get_expr)
    hidden_proto(semanage_fcontext_set_expr)
    hidden_proto(semanage_fcontext_get_type)
    hidden_proto(semanage_fcontext_get_type_str)
    hidden_proto(semanage_fcontext_set_type)
    hidden_proto(semanage_fcontext_get_con)
    hidden_proto(semanage_fcontext_set_con)
    hidden_proto(semanage_fcontext_clone)
    hidden_proto(semanage_fcontext_free)
    hidden_proto(semanage_fcontext_iterate_local)

/* FCONTEXT RECORD: metod table */
extern record_table_t SEMANAGE_FCONTEXT_RTABLE;

extern int fcontext_file_dbase_init(semanage_handle_t * handle,
				    const char *path_ro,
				    const char *path_rw,
				    dbase_config_t * dconfig);

extern void fcontext_file_dbase_release(dbase_config_t * dconfig);

extern int hidden semanage_fcontext_validate_local(semanage_handle_t * handle,
						   const sepol_policydb_t *
						   policydb);

#endif
