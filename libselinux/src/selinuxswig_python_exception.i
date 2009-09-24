
%exception is_selinux_enabled {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception is_selinux_mls_enabled {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception getcon {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception getcon_raw {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception setcon {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception setcon_raw {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception getpidcon {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception getpidcon_raw {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception getprevcon {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception getprevcon_raw {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception getexeccon {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception getexeccon_raw {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception setexeccon {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception setexeccon_raw {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception getfscreatecon {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception getfscreatecon_raw {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception setfscreatecon {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception setfscreatecon_raw {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception getkeycreatecon {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception getkeycreatecon_raw {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception setkeycreatecon {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception setkeycreatecon_raw {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception getsockcreatecon {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception getsockcreatecon_raw {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception setsockcreatecon {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception setsockcreatecon_raw {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception getfilecon {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception getfilecon_raw {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception lgetfilecon {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception lgetfilecon_raw {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception fgetfilecon {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception fgetfilecon_raw {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception setfilecon {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception setfilecon_raw {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception lsetfilecon {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception lsetfilecon_raw {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception fsetfilecon {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception fsetfilecon_raw {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception getpeercon {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception getpeercon_raw {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception security_compute_av {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception security_compute_av_raw {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception security_compute_av_flags {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception security_compute_av_flags_raw {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception security_compute_create {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception security_compute_create_raw {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception security_compute_relabel {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception security_compute_relabel_raw {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception security_compute_member {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception security_compute_member_raw {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception security_compute_user {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception security_compute_user_raw {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception security_load_policy {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception security_get_initial_context {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception security_get_initial_context_raw {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception selinux_mkload_policy {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception selinux_init_load_policy {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception security_set_boolean_list {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception security_load_booleans {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception security_check_context {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception security_check_context_raw {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception security_canonicalize_context {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception security_canonicalize_context_raw {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception security_getenforce {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception security_setenforce {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception security_deny_unknown {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception security_disable {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception security_policyvers {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception security_get_boolean_names {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception security_get_boolean_pending {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception security_get_boolean_active {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception security_set_boolean {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception security_commit_booleans {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception selinux_set_mapping {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception security_av_string {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception matchpathcon_init {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception matchpathcon_init_prefix {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception matchpathcon {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception matchpathcon_index {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception matchpathcon_filespec_add {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception matchmediacon {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception selinux_getenforcemode {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception selinux_getpolicytype {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception selinux_check_passwd_access {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception checkPasswdAccess {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception selinux_check_securetty_context {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception rpm_execcon {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception is_context_customizable {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception selinux_trans_to_raw_context {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception selinux_raw_to_trans_context {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception selinux_raw_context_to_color {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception getseuserbyname {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception getseuser {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception selinux_file_context_verify {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}


%exception selinux_lsetfilecon_default {
  $action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}

