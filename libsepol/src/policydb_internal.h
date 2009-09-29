#ifndef _SEPOL_POLICYDB_INTERNAL_H_
#define _SEPOL_POLICYDB_INTERNAL_H_

#include <sepol/policydb.h>
#include "dso.h"

hidden_proto(sepol_policydb_create)
    hidden_proto(sepol_policydb_free)
extern char *policydb_target_strings[];
#endif
