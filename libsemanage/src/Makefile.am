COMMONSRC = \
	boolean_record.c	database_llist.c	interfaces_local.c	\
	ports_file.c		user_record.c		booleans_active.c	\
	database_policydb.c	interfaces_policy.c	ports_local.c		\
	users_base_file.c	booleans_activedb.c	debug.c			\
	interfaces_policydb.c	ports_policy.c		users_base_policydb.c	\
	booleans_file.c		direct_api.c		modules.c		\
	ports_policydb.c	users_extra_file.c 	booleans_local.c	\
	fcontext_record.c	node_record.c		semanage_store.c	\
	users_join.c 		booleans_policy.c	fcontexts_file.c	\
	nodes_file.c           	users_local.c		booleans_policydb.c	\
	fcontexts_local.c	nodes_local.c 		seuser_record.c		\
	users_policy.c 		context_record.c	fcontexts_policy.c	\
	nodes_policy.c		seusers_file.c 		utilities.c 		\
	database_activedb.c	genhomedircon.c		nodes_policydb.c	\
	seusers_local.c 	database.c		handle.c            	\
	parse_utils.c		seusers_policy.c 	database_file.c		\
	iface_record.c		policy_components.c	user_base_record.c 	\
	database_join.c		interfaces_file.c	port_record.c   	\
	user_extra_record.c


CLEANFILES			= $(BUILT_SOURCES)
BUILT_SOURCES 			= conf-parse.h conf-parse.c conf-scan.c
lib_LTLIBRARIES			= libsemanage.la
libsemanage_la_SOURCES		= $(COMMONSRC) conf-scan.l conf-parse.y 
libsemanage_la_CPPFLAGS 	= \
	-I$(abs_top_srcdir)/include \
	-include $(abs_top_srcdir)/libtool_compat.h
libsemanage_la_LDFLAGS		= \
	-Wl,--as-needed \
	--version-script=$(srcdir)/libsemanage.map,-z,defs \
	-version-info 1

semanage_pyexecdir		= $(pyexecdir)/semanage
semanage_pythondir		= $(pythondir)/semanage

semanage_python_PYTHON		= __init__.py
semanage_pyexec_LTLIBRARIES	= $(py_libs)
py_libs				=

SWIG_FLAGS			= -Wall -python -outdir $(srcdir)

# When the upstream tree is patched this should be removed
# and semanage.py must be renamed to __init__.py
__init__.py : semanage.py
	cp $^ $@

if enable_python
semanageswig_wrap.c: Makefile semanageswig.i semanageswig_python.i
	$(SWIG) -o $@ $(SWIG_FLAGS) -interface libpysemanage semanageswig_python.i 

py_libs				+= libpysemanage.la
libpysemanage_la_SOURCES	= semanageswig_wrap.c
libpysemanage_la_LDFLAGS	=  -Wl,--as-needed,-z,defs -lsemanage  -L$(builddir)
libpysemanage_la_DEPENDENCIES	= $(lib_LTLIBRARIES)
libpysemanage_la_CPPFLAGS	= \
	-I$(abs_top_srcdir)/include \
	-include $(abs_top_srcdir)/libtool_compat.h \
	-I@PYTHON_INCLUDE_DIR@
endif
AM_LDFLAGS			= -Wl,--as-needed
AM_YFLAGS			= -d
# "lex.yy.c" is the default output, and is also tested by configure, 
# but conf-scan.l sets the prefix itself within the file, hence in result
# allowing the configure conftest to pass but this make rule to fail.
# This is why -o lex.yy.c is given here.
AM_LFLAGS			= -o lex.yy.c -s
sysconf_DATA			= semanage.conf
