#!/bin/bash 
context=`id -Z | secon -t -l -P`
export TITLE="Sandbox $context -- `grep ^#TITLE: ~/.sandboxrc | /usr/bin/cut -b8-80`"
export SCREENSIZE="1000x700"
#export SCREENSIZE=`xdpyinfo | awk  '/dimensions/ {  print $2 }'`
trap "exit 0" HUP

(/usr/bin/Xephyr -title "$TITLE" -terminate -screen $SCREENSIZE -displayfd 5 5>&1 2>/dev/null) | while read D; do 
    export DISPLAY=:$D
    python -c 'import gtk, os, commands; commands.getstatusoutput("%s/.sandboxrc" % os.environ["HOME"])'
    export EXITCODE=$?
    kill -HUP 0
    break
done
exit 0
