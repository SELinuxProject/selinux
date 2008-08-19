#ifndef _SEPOL_CONTEXT_INTERNAL_H_
#define _SEPOL_CONTEXT_INTERNAL_H_

#include <sepol/context_record.h>
#include "dso.h"

hidden_proto(sepol_context_clone)
    hidden_proto(sepol_context_create)
    hidden_proto(sepol_context_free)
    hidden_proto(sepol_context_from_string)
    hidden_proto(sepol_context_get_mls)
    hidden_proto(sepol_context_get_role)
    hidden_proto(sepol_context_get_type)
    hidden_proto(sepol_context_get_user)
    hidden_proto(sepol_context_set_mls)
    hidden_proto(sepol_context_set_role)
    hidden_proto(sepol_context_set_type)
    hidden_proto(sepol_context_set_user)
#endif
