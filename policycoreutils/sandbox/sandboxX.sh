#!/bin/bash 
context=`id -Z | secon -t -l -P`
export TITLE="Sandbox $context -- `grep ^#TITLE: ~/.sandboxrc | /usr/bin/cut -b8-80`"
[ $# -eq 1 ] && export SCREENSIZE="$1" || export SCREENSIZE="1000x700"
trap "exit 0" HUP

(/usr/bin/Xephyr -title "$TITLE" -terminate -screen $SCREENSIZE -displayfd 5 5>&1 2>/dev/null) | while read D; do 
    export DISPLAY=:$D
    cat > ~/seremote << __EOF
#!/bin/sh
DISPLAY=$DISPLAY "\$@"
__EOF
    chmod +x ~/seremote
    /usr/share/sandbox/start $HOME/.sandboxrc
    export EXITCODE=$?
    kill -HUP 0
    break
done
exit 0
