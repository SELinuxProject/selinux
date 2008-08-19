#ifndef _SEPOL_IFACE_INTERNAL_H_
#define _SEPOL_IFACE_INTERNAL_H_

#include <sepol/iface_record.h>
#include <sepol/interfaces.h>
#include "dso.h"

hidden_proto(sepol_iface_create)
    hidden_proto(sepol_iface_free)
    hidden_proto(sepol_iface_get_ifcon)
    hidden_proto(sepol_iface_get_msgcon)
    hidden_proto(sepol_iface_get_name)
    hidden_proto(sepol_iface_key_create)
    hidden_proto(sepol_iface_key_unpack)
    hidden_proto(sepol_iface_set_ifcon)
    hidden_proto(sepol_iface_set_msgcon)
    hidden_proto(sepol_iface_set_name)
#endif
