#ifndef _SEPOL_PORT_INTERNAL_H_
#define _SEPOL_PORT_INTERNAL_H_

#include <sepol/port_record.h>
#include <sepol/ports.h>
#include "dso.h"

hidden_proto(sepol_port_create)
    hidden_proto(sepol_port_free)
    hidden_proto(sepol_port_get_con)
    hidden_proto(sepol_port_get_high)
    hidden_proto(sepol_port_get_low)
    hidden_proto(sepol_port_get_proto)
    hidden_proto(sepol_port_get_proto_str)
    hidden_proto(sepol_port_key_create)
    hidden_proto(sepol_port_key_unpack)
    hidden_proto(sepol_port_set_con)
    hidden_proto(sepol_port_set_proto)
    hidden_proto(sepol_port_set_range)
#endif
