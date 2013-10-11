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


#['domain', 'role', 'role_prefix', 'object_class', 'name', 'private_type', 'prefix', 'entrypoint', 'target_domain', 'terminal', 'range', 'domains', 'entry_point', 'entry_file', 'domain_prefix', 'private type', 'user_prefix', 'user_role', 'user_domain', 'object', 'type', 'source_domain', 'file_type', 'file', 'class', 'peer_domain', 'objectclass(es)', 'exception_types', 'home_type', 'object_type', 'directory_type', 'boolean', 'pty_type', 'userdomain', 'tty_type', 'tmpfs_type', 'script_file', 'filetype', 'filename', 'init_script_file', 'source_role', 'userdomain_prefix']

dict_values={}
dict_values['domain'] = 'sepolicy_domain_t'
dict_values['domains'] = 'sepolicy_domain_t'
dict_values['target_domain'] = 'sepolicy_target_t'
dict_values['source_domain'] = 'sepolicy_source_t'
dict_values['peer_domain'] = 'sepolicy_peer_t'
dict_values['exception_types'] = 'sepolicy_exception_types_t'
dict_values['user_domain'] = 'sepolicy_userdomain_t'
dict_values['userdomain'] = 'sepolicy_userdomain_t'
dict_values['bool_domain'] = 'sepolicy_bool_domain_t'

dict_values['type'] = 'sepolicy_file_t'
dict_values['file_type'] = 'sepolicy_file_t'
dict_values['private type'] = 'sepolicy_private_file_t'
dict_values['private_type'] = 'sepolicy_private_file_t'
dict_values['pty_type'] = 'sepolicy_devpts_t'
dict_values['tmpfs_type'] = 'sepolicy_tmpfs_t'
dict_values['home_type'] = 'sepolicy_home_file_t'
dict_values['tty_type'] = 'sepolicy_t'
dict_values['directory_type'] = 'sepolicy_file_t'
dict_values['object_type'] = 'sepolicy_object_t'

dict_values['script_file'] = 'sepolicy_exec_t'
dict_values['entry_point'] = 'sepolicy_exec_t'
dict_values['file'] = 'sepolicy_file_t'
dict_values['entry_file'] = 'sepolicy_exec_t'
dict_values['init_script_file'] = 'sepolicy_exec_t'
dict_values['entrypoint'] = 'sepolicy_exec_t'

dict_values['role'] = 'sepolicy_r'
dict_values['role_prefix'] = 'sepolicy'
dict_values['user_role'] = 'sepolicy_r'
dict_values['source_role'] = 'sepolicy_source_r'

dict_values['prefix'] = 'sepolicy_domain'
dict_values['domain_prefix'] = 'sepolicy_domain'
dict_values['userdomain_prefix'] = 'sepolicy_userdomain'
dict_values['user_prefix'] = 'sepolicy_userdomain'

dict_values['object_class'] = 'file'
dict_values['object'] = 'file'
dict_values['class'] = 'file'
dict_values['objectclass(es)'] = 'file'
dict_values['object_name'] = 'sepolicy_object'
dict_values['name'] = '"sepolicy_name"'

dict_values['terminal'] = 'sepolicy_tty_t'
dict_values['boolean'] = 'sepolicy_bool_t'
dict_values['range'] = 's0 - mcs_systemhigh'

te_test_module="""\
policy_module(TEMPLATETYPE, 1.0.0)

type sepolicy_t;
domain_type(sepolicy_t)
type sepolicy_domain_t;
domain_type(sepolicy_domain_t)
type sepolicy_target_t;
domain_type(sepolicy_target_t)
type sepolicy_source_t;
domain_type(sepolicy_source_t)
type sepolicy_peer_t;
domain_type(sepolicy_peer_t)
type sepolicy_exception_types_t;
domain_type(sepolicy_exception_types_t)
type sepolicy_userdomain_t;
domain_type(sepolicy_userdomain_t)

type sepolicy_file_t;
files_type(sepolicy_file_t)
type sepolicy_private_file_t;
files_type(sepolicy_private_file_t)
type sepolicy_home_file_t;
files_type(sepolicy_home_file_t)
type sepolicy_tty_t;
term_tty(sepolicy_tty_t)
type sepolicy_object_t;
type sepolicy_devpts_t;
term_pty(sepolicy_devpts_t)
type sepolicy_tmpfs_t;
files_type(sepolicy_tmpfs_t)
type sepolicy_exec_t;
files_type(sepolicy_exec_t)

role sepolicy_r;
role sepolicy_source_r;
role sepolicy_target_r;

#################################
#
# Local policy
#

"""
