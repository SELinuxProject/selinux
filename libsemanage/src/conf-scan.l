/* Authors: Jason Tang     <jtang@tresys.com>
 *          James Athey    <jathey@tresys.com>
 *
 * Copyright (C) 2004-2006 Tresys Technology, LLC
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

%{
#include "conf-parse.h"

#include <ctype.h>
#include <string.h>

static char *my_strdup (char * s);
static char *my_qstrdup (char * s);

%}

%option stack prefix="semanage_"
%option noinput nounput noyy_push_state noyy_pop_state noyy_top_state noyywrap

%x arg

%%

#.*               /* ignore comments */
module-store      return MODULE_STORE;
store-root        return STORE_ROOT;
compiler-directory	return COMPILER_DIR;
ignore-module-cache return IGNORE_MODULE_CACHE;
policy-version    return VERSION;
target-platform   return TARGET_PLATFORM;
expand-check      return EXPAND_CHECK;
file-mode         return FILE_MODE;
save-previous     return SAVE_PREVIOUS;
save-linked       return SAVE_LINKED;
disable-genhomedircon return DISABLE_GENHOMEDIRCON;
usepasswd return USEPASSWD;
ignoredirs        return IGNOREDIRS;
handle-unknown    return HANDLE_UNKNOWN;
bzip-blocksize	return BZIP_BLOCKSIZE;
bzip-small	return BZIP_SMALL;
remove-hll	return REMOVE_HLL;
relabel_store	return RELABEL_STORE;
optimize-policy return OPTIMIZE_POLICY;
multiple-decls return MULTIPLE_DECLS;
"[load_policy]"   return LOAD_POLICY_START;
"[setfiles]"      return SETFILES_START;
"[sefcontext_compile]"      return SEFCONTEXT_COMPILE_START;
"[verify module]" return VERIFY_MOD_START;
"[verify linked]" return VERIFY_LINKED_START;
"[verify kernel]" return VERIFY_KERNEL_START;
"[end]"           return BLOCK_END;
path              return PROG_PATH;
args              return PROG_ARGS;
[ \t]*=[ \t]*     BEGIN arg; return '=';
[ \t\n]+          /* ignore */
.                 return semanage_text[0];
<arg>\"\"         BEGIN INITIAL; semanage_lval.s = NULL; return ARG;
<arg>\".+\"       BEGIN INITIAL; semanage_lval.s = my_qstrdup(semanage_text); return ARG;
<arg>.*[^\"\n]    BEGIN INITIAL; semanage_lval.s = my_strdup(semanage_text); return ARG;
<arg>.|\n         BEGIN INITIAL; semanage_lval.s = NULL; return ARG;

%%

/* Like strdup(), but also trim leading and trailing whitespace.
 * Returns NULL on error. */
static char *my_strdup(char *s) {
	char *t;
	while (isspace((unsigned char)*s)) {
		s++;
	}
	t = s + strlen(s) - 1;
	while (t >= s && isspace((unsigned char)*t)) {
		*t = '\0';
		t--;
	}
	return strdup(s);
}

/* strdup() a string sans initial and trailing characters.  Does /not/
 * trim any whitespace.	 Returns NULL on error. */
static char *my_qstrdup(char *s) {
	s++;
	s[strlen(s) - 1] = '\0';
	return strdup(s);
}

