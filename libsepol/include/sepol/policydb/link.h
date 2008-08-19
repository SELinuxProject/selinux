/* Authors: Jason Tang <jtang@tresys.com>
 *	    Joshua Brindle <jbrindle@tresys.com>
 *          Karl MacMillan <kmacmillan@mentalrootkit.com>
 */

#ifndef _SEPOL_POLICYDB_LINK_H
#define _SEPOL_POLICYDB_LINK_H

#include <sepol/handle.h>
#include <sepol/errcodes.h>
#include <sepol/policydb/policydb.h>


#include <stddef.h>

extern int link_modules(sepol_handle_t * handle,
			policydb_t * b, policydb_t ** mods, int len,
			int verbose);

#endif
