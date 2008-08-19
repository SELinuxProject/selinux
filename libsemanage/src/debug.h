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

#ifndef _SEMANAGE_INTERNAL_DEBUG_H_
#define _SEMANAGE_INTERNAL_DEBUG_H_

#include <stdio.h>
#include <semanage/debug.h>
#include <sepol/debug.h>
#include "handle.h"
#include "dso.h"

#define STATUS_SUCCESS 0
#define STATUS_ERR -1
#define STATUS_NODATA 1

#define msg_write(handle_arg, level_arg,                   \
	          channel_arg, func_arg, ...) do {         \
	                                                   \
        if ((handle_arg)->msg_callback) {                  \
                (handle_arg)->msg_fname = func_arg;        \
                (handle_arg)->msg_channel = channel_arg;   \
                (handle_arg)->msg_level = level_arg;       \
                                                           \
                (handle_arg)->msg_callback(                \
                        (handle_arg)->msg_callback_arg,    \
                        handle_arg, __VA_ARGS__);          \
        }                                                  \
} while(0)

#define ERR(handle, ...) \
	msg_write(handle, SEMANAGE_MSG_ERR, "libsemanage", \
	__FUNCTION__, __VA_ARGS__)

#define INFO(handle, ...) \
	msg_write(handle, SEMANAGE_MSG_INFO, "libsemanage", \
	__FUNCTION__, __VA_ARGS__)

#define WARN(handle, ...) \
	msg_write(handle, SEMANAGE_MSG_WARN, "libsemanage", \
	__FUNCTION__, __VA_ARGS__)

#ifdef __GNUC__
__attribute__ ((format(printf, 3, 4)))
#endif
extern void hidden semanage_msg_default_handler(void *varg,
						semanage_handle_t * handle,
						const char *fmt, ...);

#ifdef __GNUC__
__attribute__ ((format(printf, 3, 4)))
#endif
extern void hidden semanage_msg_relay_handler(void *varg,
					      sepol_handle_t * handle,
					      const char *fmt, ...);

hidden_proto(semanage_msg_get_channel)
    hidden_proto(semanage_msg_get_fname)
    hidden_proto(semanage_msg_get_level)
#endif
