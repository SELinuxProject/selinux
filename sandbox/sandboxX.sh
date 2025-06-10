#!/bin/bash
trap "" TERM
context=`id -Z | secon -t -l -P`
export TITLE="Sandbox $context -- `grep ^#TITLE: ~/.sandboxrc | /usr/bin/cut -b8-80`"
[ -z $1 ] && export WAYLAND_NATIVE="no" || export WAYLAND_NATIVE="$1"
[ -z $2 ] && export SCREENSIZE="1000x700" || export SCREENSIZE="$2"
[ -z $3 ] && export DPI="96" || export DPI="$3"
trap "exit 0" HUP

mkdir -p ~/.config/openbox
cat > ~/.config/openbox/rc.xml << EOF
<openbox_config xmlns="http://openbox.org/3.4/rc"
		xmlns:xi="http://www.w3.org/2001/XInclude">
<applications>
  <application class="*">
    <decor>no</decor>
    <desktop>all</desktop>
    <maximized>yes</maximized>
  </application>
</applications>
</openbox_config>
EOF

if [ "$WAYLAND_NATIVE" == "no" ]; then
    if [ -z "$WAYLAND_DISPLAY" ]; then
        DISPLAY_COMMAND='/usr/bin/Xephyr -resizeable -title "$TITLE" -terminate -screen $SCREENSIZE -dpi $DPI -nolisten tcp -displayfd 5 5>&1 2>/dev/null'
    else
        DISPLAY_COMMAND='/usr/bin/Xwayland -terminate -dpi $DPI -retro -geometry $SCREENSIZE -decorate -displayfd 5 5>&1 2>/dev/null'
    fi
    eval $DISPLAY_COMMAND | while read D; do
        export DISPLAY=:$D
        cat > ~/seremote << __EOF
#!/bin/bash -x
export DISPLAY=$DISPLAY
export WAYLAND_DISPLAY=$WAYLAND_DISPLAY
"\$@"
__EOF
        chmod +x ~/seremote
        /usr/share/sandbox/start $HOME/.sandboxrc
        export EXITCODE=$?
        kill -TERM 0
        break
    done
else
    /usr/share/sandbox/start $HOME/.sandboxrc
fi
exit 0
