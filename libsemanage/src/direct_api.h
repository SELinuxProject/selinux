/* Authors: Jason Tang <jtang@tresys.com>
 *
 * Copyright (C) 2004-2005 Tresys Technology, LLC
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

#ifndef _SEMANAGE_DIRECT_API_H_
#define _SEMANAGE_DIRECT_API_H_

/* Circular dependency */
struct semanage_handle;

/* Direct component of handle */
struct semanage_direct_handle {

	/* Locking */
	int activelock_file_fd;
	int translock_file_fd;
};

int semanage_direct_connect(struct semanage_handle *sh);

int semanage_direct_is_managed(struct semanage_handle *sh);

int semanage_direct_access_check(struct semanage_handle *sh);

int semanage_direct_mls_enabled(struct semanage_handle *sh);

#include <stdio.h>
#include <unistd.h>
ssize_t bunzip(struct semanage_handle *sh, FILE *f, char **data);

#endif
