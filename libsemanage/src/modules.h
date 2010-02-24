/* Author: Joshua Brindle <jbrindle@tresys.com>
 *         Jason Tang     <jtang@tresys.com>
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

#ifndef _SEMANAGE_INTERNAL_MODULES_H_
#define _SEMANAGE_INTERNAL_MODULES_H_

#include "module_internal.h"

struct semanage_module_info {
	char *name;		/* Key */
	char *version;
	int enabled;
};

#endif
