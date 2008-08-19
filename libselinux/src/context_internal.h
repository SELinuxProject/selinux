#include <selinux/context.h>
#include "dso.h"

hidden_proto(context_new)
    hidden_proto(context_free)
    hidden_proto(context_str)
    hidden_proto(context_type_set)
    hidden_proto(context_type_get)
    hidden_proto(context_role_set)
    hidden_proto(context_role_get)
    hidden_proto(context_user_set)
    hidden_proto(context_user_get)
    hidden_proto(context_range_set)
    hidden_proto(context_range_get)
