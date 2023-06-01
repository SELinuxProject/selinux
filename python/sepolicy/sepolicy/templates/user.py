# Copyright (C) 2007-2012 Red Hat
# see file 'COPYING' for use and warranty information
#
# policygentool is a tool for the initial generation of SELinux policy
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of the GNU General Public License as
#    published by the Free Software Foundation; either version 2 of
#    the License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
#                                        02111-1307  USA
#
#
########################### Type Enforcement File #############################

te_login_user_types="""\
policy_module(TEMPLATETYPE, 1.0.0)

########################################
#
# Declarations
#
role TEMPLATETYPE_r;

userdom_unpriv_user_template(TEMPLATETYPE)
"""

te_admin_user_types="""\
policy_module(TEMPLATETYPE, 1.0.0)

########################################
#
# Declarations
#
role TEMPLATETYPE_r;

userdom_admin_user_template(TEMPLATETYPE)
"""

te_min_login_user_types="""\
policy_module(TEMPLATETYPE, 1.0.0)

########################################
#
# Declarations
#
role TEMPLATETYPE_r;

userdom_restricted_user_template(TEMPLATETYPE)
"""

te_x_login_user_types="""\
policy_module(TEMPLATETYPE, 1.0.0)

########################################
#
# Declarations
#
role TEMPLATETYPE_r;

userdom_restricted_xwindows_user_template(TEMPLATETYPE)
"""

te_existing_user_types="""\
policy_module(TEMPLATETYPE, 1.0.0)

"""

te_root_user_types="""\
policy_module(TEMPLATETYPE, 1.0.0)

## <desc>
## <p>
## Allow TEMPLATETYPE to read files in the user home directory
## </p>
## </desc>
gen_tunable(TEMPLATETYPE_read_user_files, false)

## <desc>
## <p>
## Allow TEMPLATETYPE to manage files in the user home directory
## </p>
## </desc>
gen_tunable(TEMPLATETYPE_manage_user_files, false)

########################################
#
# Declarations
#
role TEMPLATETYPE_r;

userdom_base_user_template(TEMPLATETYPE)
"""

te_login_user_rules="""\
"""

te_existing_user_rules="""\

########################################
#
# TEMPLATETYPE customized policy
#
"""

te_x_login_user_rules="""\
"""

te_root_user_rules="""\

"""

te_transition_rules="""
optional_policy(`
        APPLICATION_role(TEMPLATETYPE_r, TEMPLATETYPE_t)
')
"""

te_user_trans_rules="""
optional_policy(`
        gen_require(`
                role USER_r;
        ')

        TEMPLATETYPE_role_change(USER_r)
')
"""

te_admin_rules="""
allow TEMPLATETYPE_t self:capability { dac_override dac_read_search kill sys_ptrace sys_nice };
files_dontaudit_search_all_dirs(TEMPLATETYPE_t)

selinux_get_enforce_mode(TEMPLATETYPE_t)
seutil_domtrans_setfiles(TEMPLATETYPE_t)
seutil_search_default_contexts(TEMPLATETYPE_t)

logging_send_syslog_msg(TEMPLATETYPE_t)

kernel_read_system_state(TEMPLATETYPE_t)

domain_dontaudit_search_all_domains_state(TEMPLATETYPE_t)
domain_dontaudit_ptrace_all_domains(TEMPLATETYPE_t)

userdom_dontaudit_search_admin_dir(TEMPLATETYPE_t)
userdom_dontaudit_search_user_home_dirs(TEMPLATETYPE_t)

tunable_policy(`TEMPLATETYPE_read_user_files',`
        userdom_read_user_home_content_files(TEMPLATETYPE_t)
        userdom_read_user_tmp_files(TEMPLATETYPE_t)
')

tunable_policy(`TEMPLATETYPE_manage_user_files',`
	userdom_manage_user_home_content_dirs(TEMPLATETYPE_t)
	userdom_manage_user_home_content_files(TEMPLATETYPE_t)
	userdom_manage_user_home_content_symlinks(TEMPLATETYPE_t)
        userdom_manage_user_tmp_files(TEMPLATETYPE_t)
')
"""

te_admin_trans_rules="""
gen_require(`
        role USER_r;
')

allow USER_r TEMPLATETYPE_r;
"""

te_admin_domain_rules="""
optional_policy(`
        APPLICATION_admin(TEMPLATETYPE_t, TEMPLATETYPE_r)
')
"""

te_roles_rules="""
optional_policy(`
        gen_require(`
                role ROLE_r;
        ')

        allow TEMPLATETYPE_r ROLE_r;
')
"""

te_sudo_rules="""
optional_policy(`
        sudo_role_template(TEMPLATETYPE, TEMPLATETYPE_r, TEMPLATETYPE_t)
')
"""

te_newrole_rules="""
seutil_run_newrole(TEMPLATETYPE_t, TEMPLATETYPE_r)
"""
