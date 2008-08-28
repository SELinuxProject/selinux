#!/bin/bash

echo -n "Autoreconfiguring..."
if autoreconf -iv &> /dev/null ; then
	echo "Done"
	if test -n "$CONFIGURE" ; then
		./configure $@
	fi
else
	echo "Error"
	autoreconf -v
fi

