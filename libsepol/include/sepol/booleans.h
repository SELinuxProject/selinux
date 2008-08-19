#ifndef _SEPOL_BOOLEANS_H_
#define _SEPOL_BOOLEANS_H_

#include <stddef.h>
#include <sepol/policydb.h>
#include <sepol/boolean_record.h>
#include <sepol/handle.h>

/*--------------compatibility--------------*/

/* Given an existing binary policy (starting at 'data', with length 'len')
   and a boolean configuration file named by 'boolpath', rewrite the binary
   policy for the boolean settings in the boolean configuration file.
   The binary policy is rewritten in place in memory.
   Returns 0 upon success, or -1 otherwise. */
extern int sepol_genbools(void *data, size_t len, char *boolpath);

/* Given an existing binary policy (starting at 'data', with length 'len')
   and boolean settings specified by the parallel arrays ('names', 'values')
   with 'nel' elements, rewrite the binary policy for the boolean settings.
   The binary policy is rewritten in place in memory.
   Returns 0 upon success or -1 otherwise. */
extern int sepol_genbools_array(void *data, size_t len,
				char **names, int *values, int nel);
/*---------------end compatbility------------*/

/* Set the specified boolean */
extern int sepol_bool_set(sepol_handle_t * handle,
			  sepol_policydb_t * policydb,
			  const sepol_bool_key_t * key,
			  const sepol_bool_t * data);

/* Return the number of booleans */
extern int sepol_bool_count(sepol_handle_t * handle,
			    const sepol_policydb_t * p, unsigned int *response);

/* Check if the specified boolean exists */
extern int sepol_bool_exists(sepol_handle_t * handle,
			     const sepol_policydb_t * policydb,
			     const sepol_bool_key_t * key, int *response);

/* Query a boolean - returns the boolean, or NULL if not found */
extern int sepol_bool_query(sepol_handle_t * handle,
			    const sepol_policydb_t * p,
			    const sepol_bool_key_t * key,
			    sepol_bool_t ** response);

/* Iterate the booleans
 * The handler may return:
 * -1 to signal an error condition,
 * 1 to signal successful exit
 * 0 to signal continue */

extern int sepol_bool_iterate(sepol_handle_t * handle,
			      const sepol_policydb_t * policydb,
			      int (*fn) (const sepol_bool_t * boolean,
					 void *fn_arg), void *arg);

#endif
