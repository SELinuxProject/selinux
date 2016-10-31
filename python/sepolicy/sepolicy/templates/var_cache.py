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
########################### cache Template File #############################

########################### Type Enforcement File #############################
te_types="""
type TEMPLATETYPE_cache_t;
files_type(TEMPLATETYPE_cache_t)
"""
te_rules="""
manage_dirs_pattern(TEMPLATETYPE_t, TEMPLATETYPE_cache_t, TEMPLATETYPE_cache_t)
manage_files_pattern(TEMPLATETYPE_t, TEMPLATETYPE_cache_t, TEMPLATETYPE_cache_t)
manage_lnk_files_pattern(TEMPLATETYPE_t, TEMPLATETYPE_cache_t, TEMPLATETYPE_cache_t)
files_var_filetrans(TEMPLATETYPE_t, TEMPLATETYPE_cache_t, { dir file lnk_file })
"""

te_stream_rules="""\
manage_sock_files_pattern(TEMPLATETYPE_t, TEMPLATETYPE_cache_t, TEMPLATETYPE_cache_t)
files_var_filetrans(TEMPLATETYPE_t, TEMPLATETYPE_cache_t, sock_file)
"""

########################### Interface File #############################
if_rules="""
########################################
## <summary>
##	Search TEMPLATETYPE cache directories.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_search_cache',`
	gen_require(`
		type TEMPLATETYPE_cache_t;
	')

	allow $1 TEMPLATETYPE_cache_t:dir search_dir_perms;
	files_search_var($1)
')

########################################
## <summary>
##	Read TEMPLATETYPE cache files.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_read_cache_files',`
	gen_require(`
		type TEMPLATETYPE_cache_t;
	')

	files_search_var($1)
	read_files_pattern($1, TEMPLATETYPE_cache_t, TEMPLATETYPE_cache_t)
')

########################################
## <summary>
##	Create, read, write, and delete
##	TEMPLATETYPE cache files.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_manage_cache_files',`
	gen_require(`
		type TEMPLATETYPE_cache_t;
	')

	files_search_var($1)
	manage_files_pattern($1, TEMPLATETYPE_cache_t, TEMPLATETYPE_cache_t)
')

########################################
## <summary>
##	Manage TEMPLATETYPE cache dirs.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_manage_cache_dirs',`
	gen_require(`
		type TEMPLATETYPE_cache_t;
	')

	files_search_var($1)
	manage_dirs_pattern($1, TEMPLATETYPE_cache_t, TEMPLATETYPE_cache_t)
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
		type TEMPLATETYPE_t, TEMPLATETYPE_cache_t;
	')

	stream_connect_pattern($1, TEMPLATETYPE_cache_t, TEMPLATETYPE_cache_t)
')
"""

if_admin_types="""
		type TEMPLATETYPE_cache_t;"""

if_admin_rules="""
	files_search_var($1)
	admin_pattern($1, TEMPLATETYPE_cache_t)
"""

########################### File Context ##################################
fc_file="""\
FILENAME		--	gen_context(system_u:object_r:TEMPLATETYPE_cache_t,s0)
"""

fc_dir="""\
FILENAME(/.*)?		gen_context(system_u:object_r:TEMPLATETYPE_cache_t,s0)
"""
