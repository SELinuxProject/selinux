/* Authors: Jason Tang <jtang@tresys.com>
 *	    Joshua Brindle <jbrindle@tresys.com>
 *          Karl MacMillan <kmacmillan@tresys.com>
 *
 * A set of utility functions that aid policy decision when dealing
 * with hierarchal items.
 *
 * Copyright (C) 2005 Tresys Technology, LLC
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _SEPOL_POLICYDB_LINK_H
#define _SEPOL_POLICYDB_LINK_H

#include <sepol/handle.h>
#include <sepol/policydb/policydb.h>
#include <stddef.h>

/* error codes */
#define SEPOL_LINK_ERROR      1	/* general error */
#define SEPOL_LINK_NOTSUP     2	/* feature not supported in module language */
#define SEPOL_LINK_REQNOTMET  3	/* requirements not met */

extern int link_modules(sepol_handle_t * handle,
			policydb_t * b, policydb_t ** mods, int len,
			int verbose);

#endif
