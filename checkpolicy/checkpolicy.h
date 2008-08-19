#ifndef _CHECKPOLICY_H_
#define _CHECKPOLICY_H_

#include <sepol/policydb/ebitmap.h>

typedef struct te_assert {
	ebitmap_t stypes;
	ebitmap_t ttypes;
	ebitmap_t tclasses;
	int self;
	sepol_access_vector_t *avp;
	unsigned long line;
	struct te_assert *next;
} te_assert_t;

te_assert_t *te_assertions;

extern unsigned int policyvers;

#endif
