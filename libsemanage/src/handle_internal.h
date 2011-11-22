#ifndef _SEMANAGE_HANDLE_INTERNAL_H_
#define _SEMANAGE_HANDLE_INTERNAL_H_

#include <semanage/handle.h>
#include "dso.h"

hidden_proto(semanage_begin_transaction)
    hidden_proto(semanage_handle_destroy)
    hidden_proto(semanage_reload_policy)
    hidden_proto(semanage_access_check)
    hidden_proto(semanage_set_root)
#endif
