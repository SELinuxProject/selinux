subdirs=module uavc policy

all:
	for i in $(subdirs) ; do make -C $$i || exit 1 ; done
