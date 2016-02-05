/* Author: Joshua Brindle <jbrindle@tresys.co
 *         Jason Tang     <jtang@tresys.com>
 *         Ivan Gyurdiev  <ivg2@cornell.edu> 
 *
 * Copyright (C) 2004-2005 Tresys Technology, LLC
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

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "handle.h"
#include "debug.h"

int semanage_msg_get_level(semanage_handle_t * handle)
{
	return handle->msg_level;
}

hidden_def(semanage_msg_get_level)

const char *semanage_msg_get_channel(semanage_handle_t * handle)
{
	return handle->msg_channel;
}

hidden_def(semanage_msg_get_channel)

const char *semanage_msg_get_fname(semanage_handle_t * handle)
{
	return handle->msg_fname;
}

hidden_def(semanage_msg_get_fname)
#ifdef __GNUC__
    __attribute__ ((format(printf, 3, 4)))
#endif
void hidden semanage_msg_default_handler(void *varg __attribute__ ((unused)),
					 semanage_handle_t * handle,
					 const char *fmt, ...)
{

	FILE *stream = NULL;
	int errsv = 0;

	switch (semanage_msg_get_level(handle)) {

	case SEMANAGE_MSG_ERR:
		stream = stderr;
		errsv = errno;
		break;
	case SEMANAGE_MSG_WARN:
		stream = stderr;
		break;
	default:
		stream = stdout;
		break;
	}

	fprintf(stream, "%s.%s: ",
		semanage_msg_get_channel(handle),
		semanage_msg_get_fname(handle));

	va_list ap;
	va_start(ap, fmt);
	vfprintf(stream, fmt, ap);
	va_end(ap);

	if (errsv && errsv != ENOMEM)
		fprintf(stream, " (%s).", strerror(errsv));

	fprintf(stream, "\n");
}

#ifdef __GNUC__
__attribute__ ((format(printf, 3, 4)))
#endif
void hidden semanage_msg_relay_handler(void *varg,
				       sepol_handle_t * sepolh,
				       const char *fmt, ...)
{
	va_list ap;
	semanage_handle_t *sh = varg;
	char buffer[1024];

	if (!sh->msg_callback)
		return;

	va_start(ap, fmt);
	vsnprintf(buffer, sizeof(buffer), fmt, ap);
	va_end(ap);

	sh->msg_fname = sepol_msg_get_fname(sepolh);
	sh->msg_channel = sepol_msg_get_channel(sepolh);
	sh->msg_level = sepol_msg_get_level(sepolh);	/* XXX should map values */
	sh->msg_callback(sh->msg_callback_arg, sh, "%s", buffer);
	return;
}

extern void semanage_msg_set_callback(semanage_handle_t * handle,
#ifdef __GNUC__
				      __attribute__ ((format(printf, 3, 4)))
#endif
				      void (*msg_callback) (void *varg,
							    semanage_handle_t *
							    handle,
							    const char *fmt,
							    ...),
				      void *msg_callback_arg)
{

	handle->msg_callback = msg_callback;
	handle->msg_callback_arg = msg_callback_arg;
}
