/* Author: Jason Tang	  <jtang@tresys.com>
 *         Christopher Ashworth <cashworth@tresys.com>
 *         Ondrej Mosnacek <omosnacek@gmail.com>
 *
 * Copyright (C) 2004-2006 Tresys Technology, LLC
 * Copyright (C) 2005-2021 Red Hat, Inc.
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

#ifndef _SEMANAGE_CIL_FILE_H_
#define _SEMANAGE_CIL_FILE_H_

#include <sys/mman.h>
#include <sys/types.h>

#include "handle.h"

struct file_contents {
	void *data; /** file contents (uncompressed) */
	size_t len; /** length of contents */
	int compressed; /** whether file was compressed */
};

/**
 * Map/read a possibly-compressed file into memory.
 *
 * If the file is bzip compressed map_file will uncompress the file into
 * @p contents. The caller is responsible for calling
 * @ref unmap_compressed_file on @p contents on success.
 *
 * @param sh        semanage handle
 * @param path      path to the file
 * @param contents  pointer to struct file_contents, which will be
 *   populated with data pointer, size, and an indication whether
 *   the file was compressed or not
 *
 * @return 0 on success, -1 otherwise.
 */
int map_compressed_file(semanage_handle_t *sh, const char *path,
			struct file_contents *contents);

/**
 * Destroy a previously mapped possibly-compressed file.
 *
 * If all fields of @p contents are zero/NULL, the function is
 * guaranteed to do nothing.
 *
 * @param contents  pointer to struct file_contents to destroy
 */
void unmap_compressed_file(struct file_contents *contents);

/**
 * Write bytes into a file, using compression if configured.
 *
 * @param sh    semanage handle
 * @param path  path to the file
 * @param data  pointer to the data
 * @param len   length of the data
 *
 * @return 0 on success, -1 otherwise.
 */
int write_compressed_file(semanage_handle_t *sh, const char *path,
			  void *data, size_t len);

#endif
