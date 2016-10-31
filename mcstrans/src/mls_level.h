#ifndef __mls_level_h__
#define __mls_level_h__

#include <sepol/policydb/mls_types.h>

unsigned int mls_compute_string_len(mls_level_t *r);
mls_level_t *mls_level_from_string(char *mls_context);
char *mls_level_to_string(mls_level_t *r);

#endif
