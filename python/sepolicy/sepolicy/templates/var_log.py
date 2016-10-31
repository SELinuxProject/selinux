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
########################### var_log Template File #############################

########################### Type Enforcement File #############################
te_types="""
type TEMPLATETYPE_log_t;
logging_log_file(TEMPLATETYPE_log_t)
"""

te_rules="""
manage_dirs_pattern(TEMPLATETYPE_t, TEMPLATETYPE_log_t, TEMPLATETYPE_log_t)
manage_files_pattern(TEMPLATETYPE_t, TEMPLATETYPE_log_t, TEMPLATETYPE_log_t)
manage_lnk_files_pattern(TEMPLATETYPE_t, TEMPLATETYPE_log_t, TEMPLATETYPE_log_t)
logging_log_filetrans(TEMPLATETYPE_t, TEMPLATETYPE_log_t, { dir file lnk_file })
"""

########################### Interface File #############################
if_rules="""\
########################################
## <summary>
##	Read TEMPLATETYPE's log files.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
## <rolecap/>
#
interface(`TEMPLATETYPE_read_log',`
	gen_require(`
		type TEMPLATETYPE_log_t;
	')

	logging_search_logs($1)
	read_files_pattern($1, TEMPLATETYPE_log_t, TEMPLATETYPE_log_t)
')

########################################
## <summary>
##	Append to TEMPLATETYPE log files.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_append_log',`
	gen_require(`
		type TEMPLATETYPE_log_t;
	')

	logging_search_logs($1)
	append_files_pattern($1, TEMPLATETYPE_log_t, TEMPLATETYPE_log_t)
')

########################################
## <summary>
##	Manage TEMPLATETYPE log files
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_manage_log',`
	gen_require(`
		type TEMPLATETYPE_log_t;
	')

	logging_search_logs($1)
	manage_dirs_pattern($1, TEMPLATETYPE_log_t, TEMPLATETYPE_log_t)
	manage_files_pattern($1, TEMPLATETYPE_log_t, TEMPLATETYPE_log_t)
	manage_lnk_files_pattern($1, TEMPLATETYPE_log_t, TEMPLATETYPE_log_t)
')
"""

if_admin_types="""
		type TEMPLATETYPE_log_t;"""

if_admin_rules="""
	logging_search_logs($1)
	admin_pattern($1, TEMPLATETYPE_log_t)
"""

########################### File Context ##################################
fc_file="""\
FILENAME		--	gen_context(system_u:object_r:TEMPLATETYPE_log_t,s0)
"""

fc_dir="""\
FILENAME(/.*)?		gen_context(system_u:object_r:TEMPLATETYPE_log_t,s0)
"""
