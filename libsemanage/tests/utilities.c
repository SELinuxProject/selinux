/* Authors: Christopher Ashworth <cashworth@tresys.com>
 *
 * Copyright (C) 2006 Tresys Technology, LLC
 * Copyright (C) 2019 Red Hat, Inc.
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
#include "handle.h"
#include <limits.h>

static int test_store_enabled = 0;

semanage_handle_t *sh = NULL;

/* Silence any error output caused by our tests
 * by using this dummy function to catch messages.
 */
void test_msg_handler(__attribute__((unused)) void *varg,
		      __attribute__((unused)) semanage_handle_t *handle,
		      __attribute__((unused)) const char *fmt, ...)
{
}

int create_test_store(void)
{
	FILE *fptr;
	const char *setfiles = getenv("SEMANAGE_TEST_SETFILES");

	if (mkdir("test-policy", 0700) < 0)
		return -1;

	if (mkdir("test-policy/store", 0700) < 0)
		return -1;

	if (mkdir("test-policy/store/active", 0700) < 0)
		return -1;

	if (mkdir("test-policy/store/active/modules", 0700) < 0)
		return -1;

	if (mkdir("test-policy/etc", 0700) < 0)
		return -1;

	if (mkdir("test-policy/etc/selinux", 0700) < 0)
		return -1;

	fptr = fopen("test-policy/etc/selinux/semanage.conf", "w+");

	if (!fptr)
		return -1;

	if (setfiles && fprintf(fptr,
				"[setfiles]\npath = %s\n"
				"args = -q -c $@ $<\n[end]\n",
				setfiles) < 0) {
		fclose(fptr);
		return -1;
	}
	fclose(fptr);

	enable_test_store();
	return 0;
}

void disable_test_store(void)
{
	test_store_enabled = 0;
}

void enable_test_store(void)
{
	test_store_enabled = 1;
}

static int write_test_policy(char *data, size_t data_len)
{
	FILE *fptr = fopen("test-policy/store/active/policy.kern", "wb+");

	if (!fptr) {
		perror("fopen");
		return -1;
	}

	if (fwrite(data, data_len, 1, fptr) != 1) {
		perror("fwrite");
		fclose(fptr);
		return -1;
	}

	fclose(fptr);

	return 0;
}

int write_test_policy_from_file(const char *filename)
{
	char *buf = NULL;
	char *source = NULL;
	char *extension;
	long source_len;
	size_t len = 0;
	FILE *fptr = fopen(filename, "rb");
	int rc;

	if (!fptr) {
		perror("fopen");
		return -1;
	}

	fseek(fptr, 0, SEEK_END);
	len = ftell(fptr);
	fseek(fptr, 0, SEEK_SET);

	buf = (char *)malloc(len);

	if (!buf) {
		perror("malloc");
		fclose(fptr);
		return -1;
	}

	fread(buf, len, 1, fptr);
	fclose(fptr);

	rc = write_test_policy(buf, len);
	free(buf);
	if (rc < 0)
		return rc;

	/* Commits need module sources, not just a queryable binary policy. */
	source = strdup(filename);
	if (!source)
		return -1;
	extension = strrchr(source, '.');
	if (!extension || strcmp(extension, ".policy")) {
		free(source);
		return -1;
	}
	strcpy(extension, ".cil");
	fptr = fopen(source, "rb");
	free(source);
	if (!fptr)
		return -1;
	if (fseek(fptr, 0, SEEK_END) != 0) {
		fclose(fptr);
		return -1;
	}
	source_len = ftell(fptr);
	if (source_len < 0 || (unsigned long)source_len > UINT_MAX ||
	    fseek(fptr, 0, SEEK_SET) != 0) {
		fclose(fptr);
		return -1;
	}
	buf = malloc((size_t)source_len + 1);
	if (!buf) {
		fclose(fptr);
		return -1;
	}
	if (fread(buf, 1, (size_t)source_len, fptr) != (size_t)source_len) {
		free(buf);
		fclose(fptr);
		return -1;
	}
	fclose(fptr);
	rc = write_test_policy_src((unsigned char *)buf,
				   (unsigned int)source_len);
	free(buf);
	return rc;
}

int write_test_policy_src(unsigned char *data, unsigned int data_len)
{
	if (mkdir("test-policy/store/active/modules/100", 0700) < 0)
		return -1;

	if (mkdir("test-policy/store/active/modules/100/base", 0700) < 0)
		return -1;

	FILE *fptr =
		fopen("test-policy/store/active/modules/100/base/cil", "w+");

	if (!fptr) {
		perror("fopen");
		return -1;
	}

	if (fwrite(data, data_len, 1, fptr) != 1) {
		perror("fwrite");
		fclose(fptr);
		return -1;
	}

	fclose(fptr);

	fptr = fopen("test-policy/store/active/modules/100/base/lang_ext",
		     "w+");

	if (!fptr) {
		perror("fopen");
		return -1;
	}

	if (fwrite("cil", sizeof("cil"), 1, fptr) != 1) {
		perror("fwrite");
		fclose(fptr);
		return -1;
	}

	fclose(fptr);

	return 0;
}

int destroy_test_store(void)
{
	FTS *ftsp = NULL;
	FTSENT *curr = NULL;
	int ret = 0;

	disable_test_store();

	char *files[] = { (char *)"test-policy", NULL };

	ftsp = fts_open(files, FTS_NOCHDIR | FTS_PHYSICAL | FTS_XDEV, NULL);

	if (!ftsp)
		return -1;

	while ((curr = fts_read(ftsp)))
		switch (curr->fts_info) {
		case FTS_DP:
		case FTS_F:
		case FTS_SL:
		case FTS_SLNONE:
		case FTS_DEFAULT:
			if (remove(curr->fts_accpath) < 0)
				ret = -1;
		default:
			break;
		}

	fts_close(ftsp);

	return ret;
}

void helper_handle_create(void)
{
	if (test_store_enabled) {
		char *root = realpath("test-policy", NULL);
		CU_ASSERT_PTR_NOT_NULL_FATAL(root);
		CU_ASSERT(semanage_set_root(root) == 0);
		free(root);
	}

	sh = semanage_handle_create();
	CU_ASSERT_PTR_NOT_NULL(sh);

	if (!getenv("SEMANAGE_TEST_VERBOSE"))
		semanage_msg_set_callback(sh, test_msg_handler, NULL);

	if (test_store_enabled) {
		sh->conf->disable_genhomedircon = 1;
		sh->conf->relabel_store = 0;
		semanage_set_create_store(sh, 1);
		semanage_set_reload(sh, 0);
		semanage_set_store_root(sh, "");
		semanage_select_store(sh, "store", SEMANAGE_CON_DIRECT);
	}
}

void helper_handle_destroy(void)
{
	semanage_handle_destroy(sh);
}

void helper_connect(void)
{
	CU_ASSERT(semanage_connect(sh) >= 0);
}

void helper_disconnect(void)
{
	CU_ASSERT(semanage_disconnect(sh) >= 0);
}

void helper_begin_transaction(void)
{
	CU_ASSERT(semanage_begin_transaction(sh) >= 0);
}

void helper_commit(void)
{
	CU_ASSERT(semanage_commit(sh) >= 0);
}

void setup_handle(level_t level)
{
	if (level >= SH_NULL)
		sh = NULL;

	if (level >= SH_HANDLE)
		helper_handle_create();

	if (level >= SH_CONNECT)
		helper_connect();

	if (level >= SH_TRANS)
		helper_begin_transaction();
}

void cleanup_handle(level_t level)
{
	if (level >= SH_TRANS)
		helper_commit();

	if (level >= SH_CONNECT)
		helper_disconnect();

	if (level >= SH_HANDLE)
		helper_handle_destroy();

	if (level >= SH_NULL)
		sh = NULL;
}

void setup_handle_invalid_store(level_t level)
{
	CU_ASSERT(level >= SH_HANDLE);

	helper_handle_create();

	semanage_select_store(sh, "", SEMANAGE_CON_INVALID);

	if (level >= SH_CONNECT)
		helper_connect();

	if (level >= SH_TRANS)
		helper_begin_transaction();
}
