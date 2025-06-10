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

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <unistd.h>
#include <fcntl.h>

#include <bzlib.h>

#include "compressed_file.h"

#include "debug.h"

#define BZ2_MAGICSTR "BZh"
#define BZ2_MAGICLEN (sizeof(BZ2_MAGICSTR)-1)

/* bzip() a data to a file, returning the total number of compressed bytes
 * in the file.  Returns -1 if file could not be compressed. */
static int bzip(semanage_handle_t *sh, const char *filename, void *data,
		size_t num_bytes)
{
	BZFILE* b;
	size_t  size = 1<<16;
	int     bzerror;
	size_t  total = 0;
	size_t len;
	FILE *f;

	if ((f = fopen(filename, "wbe")) == NULL) {
		return -1;
	}

	if (!sh->conf->bzip_blocksize) {
		if (fwrite(data, 1, num_bytes, f) < num_bytes) {
			fclose(f);
			return -1;
		}
		fclose(f);
		return 0;
	}

	b = BZ2_bzWriteOpen( &bzerror, f, sh->conf->bzip_blocksize, 0, 0);
	if (bzerror != BZ_OK) {
		BZ2_bzWriteClose ( &bzerror, b, 1, 0, 0 );
		fclose(f);
		return -1;
	}

	while ( num_bytes > total ) {
		if (num_bytes - total > size) {
			len = size;
		} else {
			len = num_bytes - total;
		}
		BZ2_bzWrite ( &bzerror, b, (uint8_t *)data + total, len );
		if (bzerror == BZ_IO_ERROR) {
			BZ2_bzWriteClose ( &bzerror, b, 1, 0, 0 );
			fclose(f);
			return -1;
		}
		total += len;
	}

	BZ2_bzWriteClose ( &bzerror, b, 0, 0, 0 );
	fclose(f);
	if (bzerror == BZ_IO_ERROR) {
		return -1;
	}
	return 0;
}

/* bunzip() a file to '*data', returning the total number of uncompressed bytes
 * in the file.  Returns -1 if file could not be decompressed. */
static ssize_t bunzip(semanage_handle_t *sh, FILE *f, void **data)
{
	BZFILE*  b = NULL;
	size_t   nBuf;
	uint8_t* buf = NULL;
	size_t   size = 1<<18;
	size_t   bufsize = size;
	int      bzerror;
	size_t   total = 0;
	uint8_t* uncompress = NULL;
	uint8_t* tmpalloc = NULL;
	ssize_t  ret = -1;

	buf = malloc(bufsize);
	if (buf == NULL) {
		ERR(sh, "Failure allocating memory.");
		goto exit;
	}

	/* Check if the file is bzipped */
	bzerror = fread(buf, 1, BZ2_MAGICLEN, f);

	if (fseek(f, 0L, SEEK_SET) == -1) {
		ERR(sh, "Failure rewinding file.");
		goto exit;
	}

	if ((bzerror != BZ2_MAGICLEN) || memcmp(buf, BZ2_MAGICSTR, BZ2_MAGICLEN)) {
		goto exit;
	}

	b = BZ2_bzReadOpen ( &bzerror, f, 0, sh->conf->bzip_small, NULL, 0 );
	if ( bzerror != BZ_OK ) {
		ERR(sh, "Failure opening bz2 archive.");
		goto exit;
	}

	uncompress = malloc(size);
	if (uncompress == NULL) {
		ERR(sh, "Failure allocating memory.");
		goto exit;
	}

	while ( bzerror == BZ_OK) {
		nBuf = BZ2_bzRead ( &bzerror, b, buf, bufsize);
		if (( bzerror == BZ_OK ) || ( bzerror == BZ_STREAM_END )) {
			if (total + nBuf > size) {
				size *= 2;
				tmpalloc = realloc(uncompress, size);
				if (tmpalloc == NULL) {
					ERR(sh, "Failure allocating memory.");
					goto exit;
				}
				uncompress = tmpalloc;
			}
			memcpy(&uncompress[total], buf, nBuf);
			total += nBuf;
		}
	}
	if ( bzerror != BZ_STREAM_END ) {
		ERR(sh, "Failure reading bz2 archive.");
		goto exit;
	}

	ret = total;
	*data = uncompress;

exit:
	BZ2_bzReadClose ( &bzerror, b );
	free(buf);
	if ( ret < 0 ) {
		free(uncompress);
	}
	return ret;
}

int map_compressed_file(semanage_handle_t *sh, const char *path,
			struct file_contents *contents)
{
	ssize_t size = -1;
	void *uncompress;
	int ret = 0, fd = -1;
	FILE *file = NULL;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd == -1) {
		ERR(sh, "Unable to open %s.", path);
		return -1;
	}

	file = fdopen(fd, "r");
	if (file == NULL) {
		ERR(sh, "Unable to open %s.", path);
		close(fd);
		return -1;
	}

	if ((size = bunzip(sh, file, &uncompress)) >= 0) {
		contents->data = uncompress;
		contents->len = size;
		contents->compressed = 1;
	} else {
		struct stat sb;
		if (fstat(fd, &sb) == -1 ||
		    (uncompress = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) ==
		    MAP_FAILED) {
			ret = -1;
		} else {
			contents->data = uncompress;
			contents->len = sb.st_size;
			contents->compressed = 0;
		}
	}
	fclose(file);
	return ret;
}

void unmap_compressed_file(struct file_contents *contents)
{
	if (!contents->data)
		return;

	if (contents->compressed) {
		free(contents->data);
	} else {
		munmap(contents->data, contents->len);
	}
}

int write_compressed_file(semanage_handle_t *sh, const char *path,
			  void *data, size_t len)
{
	return bzip(sh, path, data, len);
}
