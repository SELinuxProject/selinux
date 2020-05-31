# This file is part of systemd.
#
# Copyright 2011-2013 Dan Walsh
#
# systemd is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# systemd is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with systemd; If not, see <http://www.gnu.org/licenses/>.

__contains_word () {
        local word=$1; shift
        for w in $*; do [[ $w = $word ]] && return 0; done
        return 1
}

ALL_OPTS='-l --list -S -o -n --noheading -h --help'
MANAGED_OPTS='-a --add -m --modify -d --delete -D --deleteall -C --locallist '

__get_all_stores () {
    dir -1 -F /etc/selinux/ | grep '/' | cut -d'/' -f 1
}
__get_all_ftypes () {
    echo '-- -d -c -b -s -l -p'
}
__get_all_users () { 
    seinfo -u 2> /dev/null | tail -n +3 
}
__get_all_types () { 
    seinfo -t 2> /dev/null | tail -n +3 
}
__get_all_port_types () { 
    seinfo -aport_type -x 2>/dev/null | tail -n +2 
}
__get_all_domains () { 
    seinfo -adomain -x 2>/dev/null | tail -n +2 
}
__get_all_node_types () { 
    seinfo -anode_type -x 2>/dev/null | tail -n +2 
}
__get_all_file_types () { 
    seinfo -afile_type -x 2>/dev/null | tail -n +2 
}
__get_all_roles () { 
    seinfo -r 2> /dev/null | tail -n +3
}
__get_all_stores () {
    dir -1 -F /etc/selinux/ | grep '/' | cut -d'/' -f 1
}
__get_all_modules () {
    semodule -l
}
__get_import_opts () { echo '$ALL_OPTS --f --input_file' ; }
__get_export_opts () { echo '$ALL_OPTS --f --output_file' ; }
__get_boolean_opts () { echo '$ALL_OPTS --on -off -1 -0' ; }
__get_user_opts () { echo '$ALL_OPTS $MANAGED_OPTS -L --level -r --range -R --role '; }
__get_login_opts () { echo '$ALL_OPTS $MANAGED_OPTS -s --seuser -r --range'; }
__get_port_opts () { echo '$ALL_OPTS $MANAGED_OPTS -t --type -r --range -p --proto'; }
__get_interface_opts () { echo '$ALL_OPTS $MANAGED_OPTS -t --type '; }
__get_node_opts () { echo '$ALL_OPTS $MANAGED_OPTS -t --type -M --mask -p --proto'; }
__get_fcontext_opts () { echo '$ALL_OPTS $MANAGED_OPTS -t --type -e --equal -f --ftype '; }
__get_module_opts () { echo '$ALL_OPTS $MANAGED_OPTS --enable --disable '; }
__get_dontaudit_opts () { echo '-S on off' ; }
__get_permissive_opts () { echo '$ALL_OPTS -a --add -d --delete' ; }

_semanage () {
        local command=${COMP_WORDS[1]}
        local cur=${COMP_WORDS[COMP_CWORD]} prev=${COMP_WORDS[COMP_CWORD-1]}
        local verb comps
        local -A VERBS=(
	       [BOOLEAN]='boolean'
	       [DONTAUDIT]='dontaudit'
	       [EXPORT]='export'
	       [FCONTEXT]='fcontext'
	       [IMPORT]='import'
	       [INTERFACE]='interface'
	       [LOGIN]='login'
	       [MODULE]='module'
	       [NODE]='node'
	       [PERMISSIVE]='permissive'
	       [PORT]='port'
	       [USER]='user'
        )
	if   [ "$prev" = "-a" -a "$command" = "permissive" ]; then
	        COMPREPLY=( $(compgen -W "$( __get_all_domains ) " -- "$cur") )
		return 0
	elif [ "$command" = "module" ]; then
		if [ "$prev" = "-d" ] || [ "$prev" = "--disable" ] \
		    || [ "$prev" = "-e" ] || [ "$prev" = "--enable" ] \
		    || [ "$prev" = "-r" ] || [ "$prev" = "--remove" ]; then
	            COMPREPLY=( $(compgen -W "$( __get_all_modules ) " -- "$cur") )
		    return 0
		fi
	fi
	if   [ "$verb" = "" -a "$prev" = "semanage" ]; then
                comps="${VERBS[*]}"
	elif [ "$verb" = "" -a "$prev" = "-S" -o "$prev" = "--store" ]; then
	        COMPREPLY=( $(compgen -W "$( __get_all_stores ) " -- "$cur") )
		return 0
	elif [ "$verb" = "" -a "$prev" = "-p" -o "$prev" = "--proto" ]; then
	        COMPREPLY=( $(compgen -W "tcp udp" -- "$cur") )
		return 0
	elif [ "$verb" = "" -a "$prev" = "-R" -o "$prev" = "-r" -o "$prev" = "--role" ]; then
	    if [ "$command" != "user" -o "$prev" != "-r" ]; then
	        COMPREPLY=( $(compgen -W "$( __get_all_roles ) " -- "$cur") )
		return 0
	    else
		return 0
	    fi
	elif [ "$verb" = "" -a "$prev" = "-s" -o "$prev" = "--seuser" ]; then
	        COMPREPLY=( $(compgen -W "$( __get_all_users ) " -- "$cur") )
		return 0
	elif [ "$verb" = "" -a "$prev" = "-f" -o "$prev" = "--ftype" ]; then
	        COMPREPLY=( $(compgen -W "$( __get_all_ftypes ) " -- "$cur") )
		return 0
	elif [ "$verb" = "" -a "$prev" = "-t" -o "$prev" = "--types" ]; then
	    if [ "$command" = "port" ]; then
	        COMPREPLY=( $(compgen -W "$( __get_all_port_types ) " -- "$cur") )
		return 0
	    fi
	    if [ "$command" = "fcontext" ]; then
	        COMPREPLY=( $(compgen -W "$( __get_all_file_types ) " -- "$cur") )
		return 0
	    fi
	    COMPREPLY=( $(compgen -W "$( __get_all_types ) " -- "$cur") )
	    return 0
        elif __contains_word "$command" ${VERBS[LOGIN]} ; then
                COMPREPLY=( $(compgen -W "$( __get_login_opts ) " -- "$cur") )
		return 0
        elif __contains_word "$command" ${VERBS[USER]} ; then
                COMPREPLY=( $(compgen -W "$( __get_user_opts ) " -- "$cur") )
		return 0
        elif __contains_word "$command" ${VERBS[PORT]} ; then
                COMPREPLY=( $(compgen -W "$( __get_port_opts ) " -- "$cur") )
		return 0
        elif __contains_word "$command" ${VERBS[INTERFACE]} ; then
                COMPREPLY=( $(compgen -W "$( __get_interface_opts ) " -- "$cur") )
		return 0
        elif __contains_word "$command" ${VERBS[MODULE]} ; then
                COMPREPLY=( $(compgen -W "$( __get_module_opts ) " -- "$cur") )
		return 0
        elif __contains_word "$command" ${VERBS[NODE]} ; then
                COMPREPLY=( $(compgen -W "$( __get_node_opts ) " -- "$cur") )
		return 0
        elif __contains_word "$command" ${VERBS[FCONTEXT]} ; then
                COMPREPLY=( $(compgen -W "$( __get_fcontext_opts ) " -- "$cur") )
		return 0
        elif __contains_word "$command" ${VERBS[BOOLEAN]} ; then
                COMPREPLY=( $(compgen -W "$( __get_boolean_opts ) " -- "$cur") )
		return 0
        elif __contains_word "$command" ${VERBS[PERMISSIVE]} ; then
                COMPREPLY=( $(compgen -W "$( __get_permissive_opts ) " -- "$cur") )
		return 0
        elif __contains_word "$command" ${VERBS[DONTAUDIT]} ; then
                COMPREPLY=( $(compgen -W "$( __get_dontaudit_opts ) " -- "$cur") )
		return 0
        elif __contains_word "$command" ${VERBS[IMPORT]} ; then
                COMPREPLY=( $(compgen -W "$( __get_import_opts ) " -- "$cur") )
		return 0
        elif __contains_word "$command" ${VERBS[EXPORT]} ; then
                COMPREPLY=( $(compgen -W "$( __get_export_opts ) " -- "$cur") )
		return 0
        fi
        COMPREPLY=( $(compgen -W "$comps" -- "$cur") )
        return 0
}
complete -F _semanage semanage
