/* Authors: Christopher Ashworth <cashworth@tresys.com>
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

/*  The purpose of this file is to provide some functions commonly needed 
 *  by our unit tests.
 */

#include "utilities.h"

/* Silence any error output caused by our tests
 * by using this dummy function to catch messages. 
 */
void test_msg_handler(void *varg,
		      semanage_handle_t * handle, const char *fmt, ...)
{
}
