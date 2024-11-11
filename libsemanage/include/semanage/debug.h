/* Author: Joshua Brindle <jbrindle@tresys.com>
 *         Jason Tang     <jtang@tresys.com>
 *         Ivan Gyurdiev  <ivg2@cornell.edu>
 *
 * Copyright (C) 2005 Tresys Technology, LLC
 * Copyright (C) 2005 Red Hat Inc.
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

#ifndef _SEMANAGE_DEBUG_H_
#define _SEMANAGE_DEBUG_H_

#include <semanage/handle.h>

#define SEMANAGE_MSG_ERR  1
#define SEMANAGE_MSG_WARN 2
#define SEMANAGE_MSG_INFO 3

extern int semanage_msg_get_level(semanage_handle_t * handle);

extern const char *semanage_msg_get_channel(semanage_handle_t * handle);

extern const char *semanage_msg_get_fname(semanage_handle_t * handle);

/* Set the messaging callback.
 * By the default, the callback will print
 * the message on standard output, in a
 * particular format. Passing NULL here
 * indicates that messaging should be suppressed */
extern void semanage_msg_set_callback(semanage_handle_t * handle,
#ifdef __GNUC__
				      __attribute__ ((format(printf, 3, 4)))
#endif
				      void (*msg_callback) (void *varg,
							    semanage_handle_t *
							    handle,
							    const char *fmt,
							    ...),
				      void *msg_callback_arg);

#endif
