#ifndef _SEPOL_BOOLEAN_INTERNAL_H_
#define _SEPOL_BOOLEAN_INTERNAL_H_

#include <sepol/boolean_record.h>
#include <sepol/booleans.h>
#include "dso.h"

hidden_proto(sepol_bool_key_create)
    hidden_proto(sepol_bool_key_unpack)
    hidden_proto(sepol_bool_get_name)
    hidden_proto(sepol_bool_set_name)
    hidden_proto(sepol_bool_get_value)
    hidden_proto(sepol_bool_set_value)
    hidden_proto(sepol_bool_create)
    hidden_proto(sepol_bool_free)
#endif
