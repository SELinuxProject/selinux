#ifndef _SEPOL_IBPKEY_INTERNAL_H_
#define _SEPOL_IBPKEY_INTERNAL_H_

#include <sepol/ibpkey_record.h>
#include <sepol/ibpkeys.h>
#include "dso.h"

hidden_proto(sepol_ibpkey_create)
hidden_proto(sepol_ibpkey_free)
hidden_proto(sepol_ibpkey_get_con)
hidden_proto(sepol_ibpkey_get_high)
hidden_proto(sepol_ibpkey_get_low)
hidden_proto(sepol_ibpkey_key_create)
hidden_proto(sepol_ibpkey_key_unpack)
hidden_proto(sepol_ibpkey_set_con)
hidden_proto(sepol_ibpkey_set_range)
hidden_proto(sepol_ibpkey_get_subnet_prefix)
hidden_proto(sepol_ibpkey_get_subnet_prefix_bytes)
hidden_proto(sepol_ibpkey_set_subnet_prefix)
hidden_proto(sepol_ibpkey_set_subnet_prefix_bytes)
#endif
