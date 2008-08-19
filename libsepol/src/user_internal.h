#ifndef _SEPOL_USER_INTERNAL_H_
#define _SEPOL_USER_INTERNAL_H_

#include <sepol/user_record.h>
#include <sepol/users.h>
#include "dso.h"

hidden_proto(sepol_user_add_role)
    hidden_proto(sepol_user_create)
    hidden_proto(sepol_user_free)
    hidden_proto(sepol_user_get_mlslevel)
    hidden_proto(sepol_user_get_mlsrange)
    hidden_proto(sepol_user_get_roles)
    hidden_proto(sepol_user_has_role)
    hidden_proto(sepol_user_key_create)
    hidden_proto(sepol_user_key_unpack)
    hidden_proto(sepol_user_set_mlslevel)
    hidden_proto(sepol_user_set_mlsrange)
    hidden_proto(sepol_user_set_name)
#endif
