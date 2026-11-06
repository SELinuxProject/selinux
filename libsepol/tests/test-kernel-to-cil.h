#ifndef TEST_KERNEL_TO_CIL_H__
#define TEST_KERNEL_TO_CIL_H__

#include <CUnit/Basic.h>

int kernel_to_cil_test_init(void);
int kernel_to_cil_test_cleanup(void);
int kernel_to_cil_add_tests(CU_pSuite suite);

#endif
