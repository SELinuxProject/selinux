#ifndef TEST_OCONTEXT_H__
#define TEST_OCONTEXT_H__

#include <CUnit/Basic.h>

int ocontext_test_init(void);
int ocontext_test_cleanup(void);
int ocontext_add_tests(CU_pSuite suite);

#endif
