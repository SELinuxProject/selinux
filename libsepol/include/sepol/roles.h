#ifndef _SEPOL_ROLES_H_
#define _SEPOL_ROLES_H_

#include <sys/cdefs.h>

__BEGIN_DECLS

extern int sepol_role_exists(const sepol_policydb_t * policydb,
			     const char *role, int *response);

extern int sepol_role_list(const sepol_policydb_t * policydb,
			   char ***roles, unsigned int *nroles);

__END_DECLS
#endif
