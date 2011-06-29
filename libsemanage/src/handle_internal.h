#ifndef _SEMANAGE_HANDLE_INTERNAL_H_
#define _SEMANAGE_HANDLE_INTERNAL_H_

#include <semanage/handle.h>
#include "dso.h"

hidden_proto(semanage_begin_transaction)
hidden_proto(semanage_handle_destroy)
hidden_proto(semanage_reload_policy)
hidden_proto(semanage_access_check)
hidden_proto(semanage_set_root)

extern const char *semanage_selinux_path(void);
extern const char *semanage_file_context_path();
extern const char *semanage_file_context_local_path();
extern const char *semanage_file_context_homedir_path();
extern const char *semanage_homedir_context_path();
extern const char *semanage_binary_policy_path();
extern const char *semanage_usersconf_path();
extern const char *semanage_netfilter_context_path();
extern const char *semanage_policy_root();
#endif
