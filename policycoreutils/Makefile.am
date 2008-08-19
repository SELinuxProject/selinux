SUBDIRS		= \
	setfiles	semanage	load_policy \
	newrole		secon		audit2allow \
	audit2why 	scripts		sestatus \
	semodule_link	semodule_expand \
	restorecond	semodule_package \
	$(extra_subdirs)

extra_subdirs	=
		
# needs either pam or crypt
extra_subdirs	+= run_init

extra_subdirs	+= semodule
extra_subdirs	+= setsebool
extra_subdirs	+= semodule_deps
