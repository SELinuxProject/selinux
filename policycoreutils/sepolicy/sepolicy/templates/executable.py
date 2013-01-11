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
te_daemon_types="""\
policy_module(TEMPLATETYPE, 1.0.0)

########################################
#
# Declarations
#

type TEMPLATETYPE_t;
type TEMPLATETYPE_exec_t;
init_daemon_domain(TEMPLATETYPE_t, TEMPLATETYPE_exec_t)

permissive TEMPLATETYPE_t;
"""

te_initscript_types="""
type TEMPLATETYPE_initrc_exec_t;
init_script_file(TEMPLATETYPE_initrc_exec_t)
"""

te_dbusd_types="""\
policy_module(TEMPLATETYPE, 1.0.0)

########################################
#
# Declarations
#

type TEMPLATETYPE_t;
type TEMPLATETYPE_exec_t;
domain_type(TEMPLATETYPE_t)
domain_entry_file(TEMPLATETYPE_t, TEMPLATETYPE_exec_t)
role system_r types TEMPLATETYPE_t;

permissive TEMPLATETYPE_t;
"""

te_inetd_types="""\
policy_module(TEMPLATETYPE, 1.0.0)

########################################
#
# Declarations
#

type TEMPLATETYPE_t;
type TEMPLATETYPE_exec_t;
inetd_service_domain(TEMPLATETYPE_t, TEMPLATETYPE_exec_t)

permissive TEMPLATETYPE_t;
"""

te_userapp_types="""\
policy_module(TEMPLATETYPE, 1.0.0)

########################################
#
# Declarations
#

attribute_role TEMPLATETYPE_roles;
roleattribute system_r TEMPLATETYPE_roles;

type TEMPLATETYPE_t;
type TEMPLATETYPE_exec_t;
application_domain(TEMPLATETYPE_t, TEMPLATETYPE_exec_t)

permissive TEMPLATETYPE_t;
"""

te_sandbox_types="""\
policy_module(TEMPLATETYPE, 1.0.0)

########################################
#
# Declarations
#

sandbox_x_domain_template(TEMPLATETYPE)

permissive TEMPLATETYPE_t;
permissive TEMPLATETYPE_client_t;

"""

te_cgi_types="""\
policy_module(TEMPLATETYPE, 1.0.0)

########################################
#
# Declarations
#

apache_content_template(TEMPLATETYPE)

permissive httpd_TEMPLATETYPE_script_t;
"""

te_daemon_rules="""\
allow TEMPLATETYPE_t self:fifo_file rw_fifo_file_perms;
allow TEMPLATETYPE_t self:unix_stream_socket create_stream_socket_perms;
"""

te_inetd_rules="""
"""

te_dbusd_rules="""
optional_policy(`
	dbus_system_domain(TEMPLATETYPE_t, TEMPLATETYPE_exec_t)
')
"""

te_userapp_rules="""
allow TEMPLATETYPE_t self:fifo_file manage_fifo_file_perms;
allow TEMPLATETYPE_t self:unix_stream_socket create_stream_socket_perms;
"""

te_cgi_rules="""
"""

te_sandbox_rules="""
"""

te_uid_rules="""
auth_use_nsswitch(TEMPLATETYPE_t)
"""

te_syslog_rules="""
logging_send_syslog_msg(TEMPLATETYPE_t)
"""

te_resolve_rules="""
sysnet_dns_name_resolve(TEMPLATETYPE_t)
"""

te_pam_rules="""
auth_domtrans_chk_passwd(TEMPLATETYPE_t)
"""

te_mail_rules="""
mta_send_mail(TEMPLATETYPE_t)
"""

te_dbus_rules="""
optional_policy(`
	dbus_system_bus_client(TEMPLATETYPE_t)
	dbus_connect_system_bus(TEMPLATETYPE_t)
')
"""

te_kerberos_rules="""
optional_policy(`
	kerberos_use(TEMPLATETYPE_t)
')
"""

te_manage_krb5_rcache_rules="""
optional_policy(`
	kerberos_keytab_template(TEMPLATETYPE, TEMPLATETYPE_t)
	kerberos_manage_host_rcache(TEMPLATETYPE_t)
')
"""

te_audit_rules="""
logging_send_audit_msgs(TEMPLATETYPE_t)
"""

te_run_rules="""
optional_policy(`
	gen_require(`
		type USER_t;
		role USER_r;
	')

	TEMPLATETYPE_run(USER_t, USER_r)
')
"""

te_fd_rules="""
domain_use_interactive_fds(TEMPLATETYPE_t)
"""

te_etc_rules="""
files_read_etc_files(TEMPLATETYPE_t)
"""

te_localization_rules="""
miscfiles_read_localization(TEMPLATETYPE_t)
"""

########################### Interface File #############################

if_heading_rules="""
## <summary>policy for TEMPLATETYPE</summary>"""

if_program_rules="""

########################################
## <summary>
##	Execute TEMPLATE in the TEMPLATETYPE domin.
## </summary>
## <param name=\"domain\">
## <summary>
##	Domain allowed to transition.
## </summary>
## </param>
#
interface(`TEMPLATETYPE_domtrans',`
	gen_require(`
		type TEMPLATETYPE_t, TEMPLATETYPE_exec_t;
	')

	corecmd_search_bin($1)
	domtrans_pattern($1, TEMPLATETYPE_exec_t, TEMPLATETYPE_t)
')
"""

if_user_program_rules="""
########################################
## <summary>
##	Execute TEMPLATETYPE in the TEMPLATETYPE domain, and
##	allow the specified role the TEMPLATETYPE domain.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed to transition
##	</summary>
## </param>
## <param name="role">
##	<summary>
##	The role to be allowed the TEMPLATETYPE domain.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_run',`
	gen_require(`
		type TEMPLATETYPE_t;
		attribute_role TEMPLATETYPE_roles;
	')

	TEMPLATETYPE_domtrans($1)
	roleattribute $2 TEMPLATETYPE_roles;
')

########################################
## <summary>
##	Role access for TEMPLATETYPE
## </summary>
## <param name="role">
##	<summary>
##	Role allowed access
##	</summary>
## </param>
## <param name="domain">
##	<summary>
##	User domain for the role
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_role',`
	gen_require(`
		type TEMPLATETYPE_t;
		attribute_role TEMPLATETYPE_roles;
	')

	roleattribute $1 TEMPLATETYPE_roles;

	TEMPLATETYPE_domtrans($2)

	ps_process_pattern($2, TEMPLATETYPE_t)
	allow $2 TEMPLATETYPE_t:process { signull signal sigkill };
')
"""

if_sandbox_rules="""
########################################
## <summary>
##	Execute sandbox in the TEMPLATETYPE_t domain, and
##	allow the specified role the TEMPLATETYPE_t domain.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed to transition.
##	</summary>
## </param>
## <param name="role">
##	<summary>
##	The role to be allowed the TEMPLATETYPE_t domain.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_transition',`
	gen_require(`
		type TEMPLATETYPE_t;
		type TEMPLATETYPE_client_t;
	')

	allow $1 TEMPLATETYPE_t:process { signal_perms transition };
	dontaudit $1 TEMPLATETYPE_t:process { noatsecure siginh rlimitinh };
	role $2 types TEMPLATETYPE_t;
	role $2 types TEMPLATETYPE_client_t;

	allow TEMPLATETYPE_t $1:process { sigchld signull };
	allow TEMPLATETYPE_t $1:fifo_file rw_inherited_fifo_file_perms;
	allow TEMPLATETYPE_client_t $1:process { sigchld signull };
	allow TEMPLATETYPE_client_t $1:fifo_file rw_inherited_fifo_file_perms;
')
"""

if_role_change_rules="""
########################################
## <summary>
##	Change to the TEMPLATETYPE role.
## </summary>
## <param name="role">
##	<summary>
##	Role allowed access.
##	</summary>
## </param>
## <rolecap/>
#
interface(`TEMPLATETYPE_role_change',`
	gen_require(`
		role TEMPLATETYPE_r;
	')

	allow $1 TEMPLATETYPE_r;
')
"""

if_initscript_rules="""
########################################
## <summary>
##	Execute TEMPLATETYPE server in the TEMPLATETYPE domain.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_initrc_domtrans',`
	gen_require(`
		type TEMPLATETYPE_initrc_exec_t;
	')

	init_labeled_script_domtrans($1, TEMPLATETYPE_initrc_exec_t)
')
"""

if_dbus_rules="""
########################################
## <summary>
##	Send and receive messages from
##	TEMPLATETYPE over dbus.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_dbus_chat',`
	gen_require(`
		type TEMPLATETYPE_t;
		class dbus send_msg;
	')

	allow $1 TEMPLATETYPE_t:dbus send_msg;
	allow TEMPLATETYPE_t $1:dbus send_msg;
')
"""

if_begin_admin="""
########################################
## <summary>
##	All of the rules required to administrate
##	an TEMPLATETYPE environment
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
## <param name="role">
##	<summary>
##	Role allowed access.
##	</summary>
## </param>
## <rolecap/>
#
interface(`TEMPLATETYPE_admin',`
	gen_require(`
		type TEMPLATETYPE_t;"""

if_middle_admin="""
	')

	allow $1 TEMPLATETYPE_t:process { ptrace signal_perms };
	ps_process_pattern($1, TEMPLATETYPE_t)
"""

if_initscript_admin_types="""
		type TEMPLATETYPE_initrc_exec_t;"""

if_initscript_admin="""
	TEMPLATETYPE_initrc_domtrans($1)
	domain_system_change_exemption($1)
	role_transition $2 TEMPLATETYPE_initrc_exec_t system_r;
	allow $2 system_r;
"""

if_end_admin="""\
	optional_policy(`
		systemd_passwd_agent_exec($1)
		systemd_read_fifo_file_passwd_run($1)
	')
')
"""

########################### File Context ##################################
fc_program="""\
EXECUTABLE		--	gen_context(system_u:object_r:TEMPLATETYPE_exec_t,s0)
"""

fc_user="""\
#  No file context, leave blank
"""

fc_initscript="""\
EXECUTABLE	--	gen_context(system_u:object_r:TEMPLATETYPE_initrc_exec_t,s0)
"""
