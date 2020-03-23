#ifndef _SEMANAGE_FCONTEXT_INTERNAL_H_
#define _SEMANAGE_FCONTEXT_INTERNAL_H_

#include <semanage/fcontext_record.h>
#include <semanage/fcontexts_local.h>
#include <semanage/fcontexts_policy.h>
#include <sepol/policydb.h>
#include "database.h"
#include "handle.h"

/* FCONTEXT RECORD: method table */
extern record_table_t SEMANAGE_FCONTEXT_RTABLE;

extern int fcontext_file_dbase_init(semanage_handle_t * handle,
				    const char *path_ro,
				    const char *path_rw,
				    dbase_config_t * dconfig);

extern void fcontext_file_dbase_release(dbase_config_t * dconfig);

extern int semanage_fcontext_validate_local(semanage_handle_t * handle,
						   const sepol_policydb_t *
						   policydb);

#endif
