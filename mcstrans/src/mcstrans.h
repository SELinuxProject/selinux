/* Copyright (c) 2006 Trusted Computer Solutions, Inc. */

#include <selinux/selinux.h>

extern int init_translations(void);
extern void finish_context_translations(void);
extern int trans_context(const char *, char **);
extern int untrans_context(const char *, char **);

