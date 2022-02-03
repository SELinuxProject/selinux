
%exception semanage_reload_policy {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_get_hll_compiler_path {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_get_disable_dontaudit {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_set_default_priority {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_is_managed {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_connect {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_disconnect {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_begin_transaction {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_commit {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_access_check {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_is_connected {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_mls_enabled {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_set_root {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_get_preserve_tunables {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_get_ignore_module_cache {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception select {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception pselect {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_module_install {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_module_install_file {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_module_remove {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_module_extract {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_module_list {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_module_info_create {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_module_info_destroy {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_module_info_get_priority {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_module_info_get_name {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_module_info_get_lang_ext {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_module_info_get_enabled {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_module_info_set_priority {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_module_info_set_name {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_module_info_set_lang_ext {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_module_info_set_enabled {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_module_key_create {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_module_key_destroy {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_module_key_get_name {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_module_key_get_priority {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_module_key_set_name {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_module_key_set_priority {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_module_set_enabled {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_module_get_module_info {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_module_list_all {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_module_install_info {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_module_remove_key {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_module_get_enabled {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_module_compute_checksum {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_msg_get_level {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_bool_key_create {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_bool_key_extract {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_bool_compare {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_bool_compare2 {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_bool_set_name {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_bool_get_value {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_bool_create {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_bool_clone {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_user_key_create {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_user_key_extract {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_user_compare {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_user_compare2 {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_user_set_name {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_user_set_prefix {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_user_set_mlslevel {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_user_set_mlsrange {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_user_get_num_roles {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_user_add_role {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_user_has_role {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_user_get_roles {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_user_set_roles {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_user_create {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_user_clone {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_seuser_key_create {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_seuser_key_extract {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_seuser_compare {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_seuser_compare2 {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_seuser_set_name {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_seuser_set_sename {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_seuser_set_mlsrange {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_seuser_create {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_seuser_clone {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_context_set_user {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_context_set_role {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_context_set_type {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_context_set_mls {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_context_create {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_context_clone {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_context_from_string {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_context_to_string {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_iface_compare {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_iface_compare2 {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_iface_key_create {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_iface_key_extract {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_iface_set_name {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_iface_set_ifcon {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_iface_set_msgcon {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_iface_create {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_iface_clone {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_port_compare {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_port_compare2 {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_port_key_create {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_port_key_extract {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_port_get_proto {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_port_get_low {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_port_get_high {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_port_set_con {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_port_create {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_port_clone {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibpkey_compare {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibpkey_compare2 {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibpkey_key_create {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibpkey_key_extract {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibpkey_get_subnet_prefix {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibpkey_set_subnet_prefix {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibpkey_get_low {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibpkey_get_high {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibpkey_set_con {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibpkey_create {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibpkey_clone {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibendport_compare {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibendport_compare2 {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibendport_key_create {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibendport_key_extract {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibendport_get_ibdev_name {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibendport_set_ibdev_name {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibendport_get_port {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibendport_set_con {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibendport_create {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibendport_clone {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_node_compare {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_node_compare2 {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_node_key_create {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_node_key_extract {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_node_get_addr {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_node_get_addr_bytes {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_node_set_addr {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_node_set_addr_bytes {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_node_get_mask {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_node_get_mask_bytes {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_node_set_mask {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_node_set_mask_bytes {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_node_get_proto {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_node_set_con {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_node_create {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_node_clone {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_bool_modify_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_bool_del_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_bool_query_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_bool_exists_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_bool_count_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_bool_iterate_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_bool_list_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_bool_query {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_bool_exists {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_bool_count {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_bool_iterate {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_bool_list {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_bool_set_active {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_bool_query_active {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_bool_exists_active {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_bool_count_active {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_bool_iterate_active {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_bool_list_active {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_user_modify_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_user_del_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_user_query_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_user_exists_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_user_count_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_user_iterate_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_user_list_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_user_query {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_user_exists {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_user_count {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_user_iterate {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_user_list {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_fcontext_compare {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_fcontext_compare2 {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_fcontext_key_create {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_fcontext_key_extract {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_fcontext_set_expr {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_fcontext_get_type {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_fcontext_set_con {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_fcontext_create {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_fcontext_clone {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_fcontext_modify_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_fcontext_del_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_fcontext_query_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_fcontext_exists_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_fcontext_count_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_fcontext_iterate_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_fcontext_list_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_fcontext_query {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_fcontext_exists {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_fcontext_count {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_fcontext_iterate {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_fcontext_list {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_fcontext_list_homedirs {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_seuser_modify_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_seuser_del_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_seuser_query_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_seuser_exists_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_seuser_count_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_seuser_iterate_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_seuser_list_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_seuser_query {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_seuser_exists {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_seuser_count {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_seuser_iterate {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_seuser_list {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_port_modify_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_port_del_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_port_query_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_port_exists_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_port_count_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_port_iterate_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_port_list_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_port_query {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_port_exists {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_port_count {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_port_iterate {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_port_list {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibpkey_modify_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibpkey_del_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibpkey_query_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibpkey_exists_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibpkey_count_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibpkey_iterate_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibpkey_list_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibendport_modify_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibendport_del_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibendport_query_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibendport_exists_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibendport_count_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibendport_iterate_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibendport_list_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibendport_query {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibendport_exists {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibendport_count {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibendport_iterate {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibendport_list {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibpkey_query {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibpkey_exists {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibpkey_count {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibpkey_iterate {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_ibpkey_list {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_iface_modify_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_iface_del_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_iface_query_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_iface_exists_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_iface_count_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_iface_iterate_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_iface_list_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_iface_query {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_iface_exists {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_iface_count {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_iface_iterate {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_iface_list {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_node_modify_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_node_del_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_node_query_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_node_exists_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_node_count_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_node_iterate_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_node_list_local {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_node_query {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_node_exists {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_node_count {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_node_iterate {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}

%exception semanage_node_list {
  $action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}
