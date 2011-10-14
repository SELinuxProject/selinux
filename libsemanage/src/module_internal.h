#ifndef _SEMANAGE_MODULE_INTERNAL_H_
#define _SEMANAGE_MODULE_INTERNAL_H_

#include <semanage/modules.h>
#include "dso.h"

hidden_proto(semanage_module_get_name)
    hidden_proto(semanage_module_info_datum_destroy)
    hidden_proto(semanage_module_list_nth)
    hidden_proto(semanage_module_info_create)
    hidden_proto(semanage_module_info_destroy)
    hidden_proto(semanage_module_info_get_priority)
    hidden_proto(semanage_module_info_get_name)
    hidden_proto(semanage_module_info_get_lang_ext)
    hidden_proto(semanage_module_info_get_enabled)
    hidden_proto(semanage_module_info_set_priority)
    hidden_proto(semanage_module_info_set_name)
    hidden_proto(semanage_module_info_set_lang_ext)
    hidden_proto(semanage_module_info_set_enabled)
    hidden_proto(semanage_module_key_create)
    hidden_proto(semanage_module_key_destroy)
    hidden_proto(semanage_module_key_get_priority)
    hidden_proto(semanage_module_key_get_name)
    hidden_proto(semanage_module_key_set_priority)
    hidden_proto(semanage_module_key_set_name)
    hidden_proto(semanage_module_set_enabled)
#endif
