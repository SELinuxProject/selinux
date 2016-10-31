# This file is part of systemd.
#
# Copyright 2012-2013 Dan Walsh
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

__get_all_paths () {
    dir -1 -F $* | grep '/' | cut -d'/' -f 1
}
__get_all_ftypes () {
    echo '-- -d -c -b -s -l -p'
}
__get_all_networks () {
    seinfo -u 2> /dev/null | tail -n +3
}
__get_all_booleans () {
    getsebool -a 2> /dev/null
}
__get_all_types () {
    seinfo -t 2> /dev/null | tail -n +3
}
__get_all_admin_interaces () {
    awk '/InterfaceVector.*_admin /{ print $2 }' /var/lib/sepolgen/interface_info | awk -F '_admin' '{ print $1 }'
}
__get_all_user_role_interaces () {
    awk '/InterfaceVector.*_role /{ print $2 }' /var/lib/sepolgen/interface_info | awk -F '_role' '{ print $1 }'
}
__get_all_user_domains () {
    seinfo -auserdomain -x 2> /dev/null | tail -n +2
}
__get_all_users () {
    seinfo -u 2> /dev/null | tail -n +2
}
__get_all_classes () {
    seinfo -c 2> /dev/null | tail -n +2
}
__get_all_port_types () {
    seinfo -aport_type -x 2> /dev/null | tail -n +2
}
__get_all_domain_types () {
    seinfo -adomain -x 2> /dev/null | tail -n +2
}
__get_all_domains () {
    seinfo -adomain -x 2>/dev/null | sed 's/_t$//g'
}
_sepolicy () {
        local command=${COMP_WORDS[1]}
        local cur=${COMP_WORDS[COMP_CWORD]} prev=${COMP_WORDS[COMP_CWORD-1]}
        local verb comps

        local -A VERBS=(
               [BOOLEANS]='booleans'
               [COMMUNICATE]='communicate'
               [GENERATE]='generate'
               [GUI]='gui'
               [INTERFACE]='interface'
               [MANPAGE]='manpage'
               [NETWORK]='network'
               [TRANSITION]='transition'
        )

        COMMONOPTS='-P --policy -h --help'
        local -A OPTS=(
               [booleans]='-h --help -p --path -a -all -b --boolean'
               [communicate]='-h --help -s --source -t --target -c --class -S --sourceaccess -T --targetaccess'
               [generate]='-a --admin --admin_user --application --cgi --confined_admin --customize  -d --domain --dbus --desktop_user -h --help --inetd --init -n --name --newtype -p --path --sandbox -T --test --term_user -u --user -w --writepath --x_user'
               [gui]='-h --help'
               [interface]='-h --help -a --list_admin -c --compile -i --interface -l --list -u --list_user -u --list_user -v --verbose'
               [manpage]='-h --help -p --path -a -all -o --os -d --domain -w --web -r --root'
               [network]='-h --help -d --domain -l --list -p --port -t --type '
               [transition]='-h --help -s --source -t --target'
        )

        for ((i=0; $i <= $COMP_CWORD; i++)); do
                if __contains_word "${COMP_WORDS[i]}" ${VERBS[*]} &&
                 ! __contains_word "${COMP_WORDS[i-1]}" ${OPTS[ARG}]}; then
                        verb=${COMP_WORDS[i]}
                        break
                fi
        done

        if   [[ -z $verb ]]; then
            if [ "$prev" = "-P" -o "$prev" = "--policy" ]; then
                COMPREPLY=( $( compgen -f -- "$cur") )
                compopt -o filenames
                return 0
            else
                comps="${VERBS[*]} ${COMMONOPTS}"
            fi
        elif [ "$verb" = "booleans" ]; then
            if [ "$prev" = "-b" -o "$prev" = "--boolean" ]; then
                COMPREPLY=( $(compgen -W "$( __get_all_booleans ) " -- "$cur") )
                return 0
            fi
            COMPREPLY=( $(compgen -W '${OPTS[$verb]}' -- "$cur") )
            return 0
        elif [ "$verb" = "communicate" ]; then
            if [ "$prev" = "-s" -o "$prev" = "--source" -o "$prev" = "-t" -o "$prev" = "--target" ]; then
                COMPREPLY=( $(compgen -W "$( __get_all_domain_types ) " -- "$cur") )
                return 0
            elif [ "$prev" = "-c" -o "$prev" = "--class" ]; then
                COMPREPLY=( $(compgen -W "$( __get_all_classes ) " -- "$cur") )
                return 0
            fi
            COMPREPLY=( $(compgen -W '${OPTS[$verb]}' -- "$cur") )
            return 0
        elif [ "$verb" = "generate" ]; then
            if [ "$prev" = "--name" -o "$prev" = "-n" ]; then
                return 0
            elif test "$prev" = "-p" || test "$prev" = "--path" ; then
                COMPREPLY=( $( compgen -d -- "$cur") )
                compopt -o filenames
                return 0
            elif test "$prev" = "-w" || test "$prev" = "--writepath" ; then
                COMPREPLY=( $( compgen -d -- "$cur") )
                compopt -o filenames
                return 0
            elif [ "$prev" = "--domain" -o "$prev" = "-d" ]; then
                COMPREPLY=( $(compgen -W "$( __get_all_domain_types ) " -- "$cur") )
                return 0
            elif [ "$prev" = "--newtype" ]; then
                COMPREPLY=( $(compgen -W "-n --name -t --type" -- "$cur") )
                return 0
            elif [ "$prev" = "--admin" -o "$prev" = "-a" ]; then
                COMPREPLY=( $(compgen -W "$( __get_all_admin_interaces ) " -- "$cur") )
                return 0
            elif [ "$prev" = "--user" -o "$prev" = "-u" ]; then
                COMPREPLY=( $(compgen -W "$( __get_all_users )" -- "$cur") )
                return 0
            elif [[ "$cur" == "$verb" || "$cur" == "" || "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W '${OPTS[$verb]}' -- "$cur") )
                return 0
            fi
            COMPREPLY=( $( compgen -f -- "$cur") )
            compopt -o filenames
            return 0
        elif [ "$verb" = "interface" ]; then
            COMPREPLY=( $(compgen -W '${OPTS[$verb]}' -- "$cur") )
            return 0
        elif [ "$verb" = "manpage" ]; then
            if [ "$prev" = "-d" -o "$prev" = "--domain" ]; then
                COMPREPLY=( $(compgen -W "$( __get_all_domains ) " -- "$cur") )
                return 0
            elif test "$prev" = "-r" || test "$prev" = "--root" ; then
                COMPREPLY=( $( compgen -d -- "$cur") )
                compopt -o filenames
                return 0
            elif [ "$prev" = "-o" -o "$prev" = "--os" ]; then
                return 0
            elif test "$prev" = "-p" || test "$prev" = "--path" ; then
                COMPREPLY=( $( compgen -d -- "$cur") )
                compopt -o filenames
                return 0
            fi
            COMPREPLY=( $(compgen -W '${OPTS[$verb]}' -- "$cur") )
            return 0
        elif [ "$verb" = "network" ]; then
            if [ "$prev" = "-t" -o "$prev" = "--type" ]; then
                COMPREPLY=( $(compgen -W "$( __get_all_port_types )" -- "$cur") )
                return 0
            fi
            if [ "$prev" = "-d" -o "$prev" = "--domain" ]; then
                COMPREPLY=( $(compgen -W "$( __get_all_domain_types )" -- "$cur") )
                return 0
            fi
            COMPREPLY=( $(compgen -W '${OPTS[$verb]}' -- "$cur") )
            return 0
        elif [ "$verb" = "transition" ]; then
            if [ "$prev" = "-s" -o "$prev" = "--source" -o "$prev" = "-t" -o "$prev" = "--target" ]; then
                COMPREPLY=( $(compgen -W "$( __get_all_domain_types ) " -- "$cur") )
                return 0
            fi
            COMPREPLY=( $(compgen -W '${OPTS[$verb]}' -- "$cur") )
            return 0
        fi
        COMPREPLY=( $(compgen -W "$comps" -- "$cur") )
        return 0
}
complete -F _sepolicy sepolicy
