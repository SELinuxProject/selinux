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
########################### var_spool Template File #############################

########################### Type Enforcement File #############################
te_types="""
type TEMPLATETYPE_spool_t;
files_type(TEMPLATETYPE_spool_t)
"""
te_rules="""
manage_dirs_pattern(TEMPLATETYPE_t, TEMPLATETYPE_spool_t, TEMPLATETYPE_spool_t)
manage_files_pattern(TEMPLATETYPE_t, TEMPLATETYPE_spool_t, TEMPLATETYPE_spool_t)
manage_lnk_files_pattern(TEMPLATETYPE_t, TEMPLATETYPE_spool_t, TEMPLATETYPE_spool_t)
files_spool_filetrans(TEMPLATETYPE_t, TEMPLATETYPE_spool_t, { dir file lnk_file })
"""

te_stream_rules="""\
manage_sock_files_pattern(TEMPLATETYPE_t, TEMPLATETYPE_spool_t, TEMPLATETYPE_spool_t)
files_spool_filetrans(TEMPLATETYPE_t, TEMPLATETYPE_spool_t, sock_file)
"""

########################### Interface File #############################
if_rules="""
########################################
## <summary>
##	Search TEMPLATETYPE spool directories.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_search_spool',`
	gen_require(`
		type TEMPLATETYPE_spool_t;
	')

	allow $1 TEMPLATETYPE_spool_t:dir search_dir_perms;
	files_search_spool($1)
')

########################################
## <summary>
##	Read TEMPLATETYPE spool files.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_read_spool_files',`
	gen_require(`
		type TEMPLATETYPE_spool_t;
	')

	files_search_spool($1)
	read_files_pattern($1, TEMPLATETYPE_spool_t, TEMPLATETYPE_spool_t)
')

########################################
## <summary>
##	Manage TEMPLATETYPE spool files.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_manage_spool_files',`
	gen_require(`
		type TEMPLATETYPE_spool_t;
	')

	files_search_spool($1)
	manage_files_pattern($1, TEMPLATETYPE_spool_t, TEMPLATETYPE_spool_t)
')

########################################
## <summary>
##	Manage TEMPLATETYPE spool dirs.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_manage_spool_dirs',`
	gen_require(`
		type TEMPLATETYPE_spool_t;
	')

	files_search_spool($1)
	manage_dirs_pattern($1, TEMPLATETYPE_spool_t, TEMPLATETYPE_spool_t)
')

"""

if_stream_rules="""
########################################
## <summary>
##	Connect to TEMPLATETYPE over a unix stream socket.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_stream_connect',`
	gen_require(`
		type TEMPLATETYPE_t, TEMPLATETYPE_spool_t;
	')

	stream_connect_pattern($1, TEMPLATETYPE_spool_t, TEMPLATETYPE_spool_t)
')
"""

if_admin_types="""
		type TEMPLATETYPE_spool_t;"""

if_admin_rules="""
	files_search_spool($1)
	admin_pattern($1, TEMPLATETYPE_spool_t)
"""

########################### File Context ##################################
fc_file="""\
FILENAME		--	gen_context(system_u:object_r:TEMPLATETYPE_spool_t,s0)
"""

fc_dir="""\
FILENAME(/.*)?		gen_context(system_u:object_r:TEMPLATETYPE_spool_t,s0)
"""
