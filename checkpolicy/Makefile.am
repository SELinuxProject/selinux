bin_PROGRAMS		= checkmodule checkpolicy
checkmodule_SOURCES	= $(COMMONSRC)  checkmodule.c
checkmodule_DEPENDENCIES= $(LIBSEPOL_A_PATH)
checkmodule_LDADD	= $(LIBSEPOL_A_PATH)
checkpolicy_SOURCES	= $(COMMONSRC) checkpolicy.c
checkpolicy_DEPENDENCIES= $(LIBSEPOL_A_PATH)
checkpolicy_LDADD	= $(LIBSEPOL_A_PATH)
BUILT_SOURCES		= y.tab.c y.tab.h policy_scan.c
CLEANFILES		= $(BUILT_SOURCES)
AM_LDFLAGS		= -Wl,--as-needed

COMMONSRC		= \
	queue.c		module_compiler.c \
	parse_util.c	policy_define.c \
	policy_parse.y	policy_scan.l

y.tab.h y.tab.c : policy_parse.y
	$(YACC) -d $<
