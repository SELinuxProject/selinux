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
########################### tmp Template File #############################

te_types="""
type TEMPLATETYPE_tmp_t;
files_tmp_file(TEMPLATETYPE_tmp_t)
"""

te_rules="""
manage_dirs_pattern(TEMPLATETYPE_t, TEMPLATETYPE_tmp_t, TEMPLATETYPE_tmp_t)
manage_files_pattern(TEMPLATETYPE_t, TEMPLATETYPE_tmp_t, TEMPLATETYPE_tmp_t)
manage_lnk_files_pattern(TEMPLATETYPE_t, TEMPLATETYPE_tmp_t, TEMPLATETYPE_tmp_t)
files_tmp_filetrans(TEMPLATETYPE_t, TEMPLATETYPE_tmp_t, { dir file lnk_file })
"""

te_stream_rules="""
manage_sock_files_pattern(TEMPLATETYPE_t, TEMPLATETYPE_tmp_t, TEMPLATETYPE_tmp_t)
files_tmp_filetrans(TEMPLATETYPE_t, TEMPLATETYPE_tmp_t, sock_file)
"""

if_rules="""
########################################
## <summary>
##	Do not audit attempts to read,
##	TEMPLATETYPE tmp files
## </summary>
## <param name="domain">
##	<summary>
##	Domain to not audit.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_dontaudit_read_tmp_files',`
	gen_require(`
		type TEMPLATETYPE_tmp_t;
	')

	dontaudit $1 TEMPLATETYPE_tmp_t:file read_file_perms;
')

########################################
## <summary>
##	Read TEMPLATETYPE tmp files
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_read_tmp_files',`
	gen_require(`
		type TEMPLATETYPE_tmp_t;
	')

	files_search_tmp($1)
	read_files_pattern($1, TEMPLATETYPE_tmp_t, TEMPLATETYPE_tmp_t)
')

########################################
## <summary>
##	Manage TEMPLATETYPE tmp files
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_manage_tmp',`
	gen_require(`
		type TEMPLATETYPE_tmp_t;
	')

	files_search_tmp($1)
	manage_dirs_pattern($1, TEMPLATETYPE_tmp_t, TEMPLATETYPE_tmp_t)
	manage_files_pattern($1, TEMPLATETYPE_tmp_t, TEMPLATETYPE_tmp_t)
	manage_lnk_files_pattern($1, TEMPLATETYPE_tmp_t, TEMPLATETYPE_tmp_t)
')
"""

if_stream_rules="""\
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
		type TEMPLATETYPE_t, TEMPLATETYPE_tmp_t;
	')

	files_search_pids($1)
	stream_connect_pattern($1, TEMPLATETYPE_tmp_t, TEMPLATETYPE_tmp_t, TEMPLATETYPE_t)
')
"""

if_admin_types="""
		type TEMPLATETYPE_tmp_t;"""

if_admin_rules="""
	files_search_tmp($1)
	admin_pattern($1, TEMPLATETYPE_tmp_t)
"""
