# This file is part of systemd.
#
# Copyright 2011 Dan Walsh
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

__get_all_booleans () {
    getsebool -a | cut -f1 -d' '
}

_setsebool () {
        local command=${COMP_WORDS[1]}
        local cur=${COMP_WORDS[COMP_CWORD]} prev=${COMP_WORDS[COMP_CWORD-1]}
        local verb comps

	if   [ "$verb" = "" -a "$prev" = "setsebool" -o "$prev" = "-P" ]; then
	        COMPREPLY=( $(compgen -W "-P $( __get_all_booleans ) " -- "$cur") )
		return 0
        fi
        COMPREPLY=( $(compgen -W "0 1 -P" -- "$cur") )
        return 0
}

_getsebool () {
        local command=${COMP_WORDS[1]}
        local cur=${COMP_WORDS[COMP_CWORD]} prev=${COMP_WORDS[COMP_CWORD-1]}
        local verb comps

	if   [ "$verb" = "" -a "$prev" == "getsebool" ]; then
	        COMPREPLY=( $(compgen -W "-a $( __get_all_booleans ) " -- "$cur") )
		return 0
        fi
	if   [ "$verb" = "" -a "$prev" != "-a" ]; then
	        COMPREPLY=( $(compgen -W "$( __get_all_booleans ) " -- "$cur") )
		return 0
        fi
        return 0
}

complete -F _setsebool setsebool
complete -F _getsebool getsebool
