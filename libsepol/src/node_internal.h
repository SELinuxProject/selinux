#ifndef _SEPOL_NODE_INTERNAL_H_
#define _SEPOL_NODE_INTERNAL_H_

#include <sepol/node_record.h>
#include <sepol/nodes.h>
#include "dso.h"

hidden_proto(sepol_node_create)
    hidden_proto(sepol_node_key_free)
    hidden_proto(sepol_node_free)
    hidden_proto(sepol_node_get_con)
    hidden_proto(sepol_node_get_addr)
    hidden_proto(sepol_node_get_addr_bytes)
    hidden_proto(sepol_node_get_mask)
    hidden_proto(sepol_node_get_mask_bytes)
    hidden_proto(sepol_node_get_proto)
    hidden_proto(sepol_node_get_proto_str)
    hidden_proto(sepol_node_key_create)
    hidden_proto(sepol_node_key_unpack)
    hidden_proto(sepol_node_set_con)
    hidden_proto(sepol_node_set_addr)
    hidden_proto(sepol_node_set_addr_bytes)
    hidden_proto(sepol_node_set_mask)
    hidden_proto(sepol_node_set_mask_bytes)
    hidden_proto(sepol_node_set_proto)
#endif
