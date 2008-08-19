/*
 * Author: Karl MacMillan <kmacmillan@tresys.com>
 *
 * Copyright (C) 2006 Tresys Technology, LLC
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

/* Utility functions shared by checkpolicy and checkmodule */

#ifndef __PARSE_UTIL_H__
#define __PARSE_UTIL_H__

#include <sepol/policydb/policydb.h>

/* Read a source policy and populate the policydb passed in. The
 * policydb must already have been created and configured (e.g.,
 * expected policy type set. The string progname is used for
 * error messages. No checking of assertions, hierarchy, etc.
 * is done. */
int read_source_policy(policydb_t * p, const char *file, const char *progname);

#endif
