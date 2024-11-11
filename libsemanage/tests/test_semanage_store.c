/* Authors: Christopher Ashworth <cashworth@tresys.com>
 *          Caleb Case <ccase@tresys.com>
 *          Chris PeBenito <cpebenito@tresys.com>
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

/*  The purpose of this file is to provide unit tests of the functions in:
 *
 *  libsemanage/src/semanage_store.c
 *
 */

#include "handle.h"
#include "semanage_store.h"

#include "utilities.h"
#include "test_semanage_store.h"

#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <CUnit/Basic.h>

static const char *const rootpath = "./test-policy";
static const char *const polpath = "./test-policy/store/";
static const char *const readlockpath = "./test-policy/store/semanage.read.LOCK";
static const char *const translockpath = "./test-policy/store/semanage.trans.LOCK";
static const char *const actpath = "./test-policy/store/active";
static const char *const modpath = "./test-policy/store/active/modules";

/* The suite initialization function.
 * Returns zero on success, non-zero otherwise.
 */
int semanage_store_test_init(void)
{
	int err;

	/* create directories */
	err = mkdir(rootpath, S_IRUSR | S_IWUSR | S_IXUSR);
	if (err != 0)
		return -1;

	err = mkdir(polpath, S_IRUSR | S_IWUSR | S_IXUSR);
	if (err != 0)
		return -1;

	err = mkdir(actpath, S_IRUSR | S_IWUSR | S_IXUSR);
	if (err != 0)
		return -1;

	err = mkdir(modpath, S_IRUSR | S_IWUSR | S_IXUSR);
	if (err != 0)
		return -1;

	/* initialize the handle */
	sh = semanage_handle_create();
	if (sh == NULL)
		return -1;

	/* hide error messages */
	sh->msg_callback = test_msg_handler;

	/* use our own policy store */
	free(sh->conf->store_path);
	sh->conf->store_path = strdup("store");

	/* initialize paths */
	err = semanage_check_init(sh, rootpath);
	if (err != 0)
		return -1;

	return 0;
}

/* The suite cleanup function.
 * Returns zero on success, non-zero otherwise.
 */
int semanage_store_test_cleanup(void)
{
	int err;

	/* remove the test policy directories */
	err = rmdir(modpath);
	if (err != 0)
		return -1;

	err = rmdir(actpath);
	if (err != 0)
		return -1;

	err = rmdir(polpath);
	if (err != 0)
		return -1;

	err = rmdir(rootpath);
	if (err != 0)
		return -1;

	/* cleanup the handle */
	semanage_handle_destroy(sh);
	return 0;
}

/* Adds all the tests needed for this suite.
 */
int semanage_store_add_tests(CU_pSuite suite)
{
	if (NULL ==
	    CU_add_test(suite, "semanage_store_access_check",
			test_semanage_store_access_check)) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	if (NULL ==
	    CU_add_test(suite, "semanage_get_lock", test_semanage_get_lock)) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	if (NULL ==
	    CU_add_test(suite, "semanage_nc_sort", test_semanage_nc_sort)) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	return 0;
}

/* Tests the semanage_store_access_check function in semanage_store.c
 */
void test_semanage_store_access_check(void)
{
	int err;

	/* create lock file */
	err = mknod(readlockpath, S_IRUSR | S_IWUSR, S_IFREG);

	/* check with permissions 000 */
	err = chmod(modpath, 0);
	CU_ASSERT(err == 0);
	err = chmod(readlockpath, 0);
	CU_ASSERT(err == 0);
	err = chmod(polpath, 0);
	CU_ASSERT(err == 0);

	err = semanage_store_access_check();
	CU_ASSERT(err == -1);

	/* check with permissions 500 */
	err = chmod(polpath, S_IRUSR | S_IXUSR);
	CU_ASSERT(err == 0);
	err = chmod(readlockpath, S_IRUSR);
	CU_ASSERT(err == 0);
	err = chmod(modpath, S_IRUSR | S_IXUSR);
	CU_ASSERT(err == 0);

	err = semanage_store_access_check();
	CU_ASSERT(err == SEMANAGE_CAN_READ);

	/* check with permissions 700 */
	err = chmod(polpath, S_IRUSR | S_IWUSR | S_IXUSR);
	CU_ASSERT(err == 0);
	err = chmod(readlockpath, S_IRUSR | S_IWUSR);
	CU_ASSERT(err == 0);
	err = chmod(modpath, S_IRUSR | S_IWUSR | S_IXUSR);
	CU_ASSERT(err == 0);

	err = semanage_store_access_check();
	CU_ASSERT(err == SEMANAGE_CAN_WRITE);

	/* check with lock file 000 and others 500 */
	err = chmod(polpath, S_IRUSR | S_IXUSR);
	CU_ASSERT(err == 0);
	err = chmod(readlockpath, 0);
	CU_ASSERT(err == 0);
	err = chmod(modpath, S_IRUSR | S_IXUSR);
	CU_ASSERT(err == 0);

	err = semanage_store_access_check();
	CU_ASSERT(err == 0);

	/* check with lock file 000 and others 700 */
	err = chmod(polpath, S_IRUSR | S_IWUSR | S_IXUSR);
	CU_ASSERT(err == 0);
	err = chmod(readlockpath, 0);
	CU_ASSERT(err == 0);
	err = chmod(modpath, S_IRUSR | S_IWUSR | S_IXUSR);
	CU_ASSERT(err == 0);

	err = semanage_store_access_check();
	CU_ASSERT(err == 0);

	/* remove lock file */
	err = remove(readlockpath);
	CU_ASSERT(err == 0);

	/* check with no lock file and 000 */
	err = chmod(modpath, 0);
	CU_ASSERT(err == 0);
	err = chmod(polpath, 0);
	CU_ASSERT(err == 0);

	err = semanage_store_access_check();
	CU_ASSERT(err == -1);

	/* check with no lock file and 500 */
	err = chmod(polpath, S_IRUSR | S_IXUSR);
	CU_ASSERT(err == 0);
	err = chmod(modpath, S_IRUSR | S_IXUSR);
	CU_ASSERT(err == 0);

	err = semanage_store_access_check();
	CU_ASSERT(err == 0);

	/* check with no lock file but write in polpath */
	err = chmod(polpath, S_IRUSR | S_IWUSR | S_IXUSR);
	CU_ASSERT(err == 0);

	err = semanage_store_access_check();
	CU_ASSERT(err == SEMANAGE_CAN_READ);

	/* check with no lock file and 700 */
	err = chmod(polpath, S_IRUSR | S_IWUSR | S_IXUSR);
	CU_ASSERT(err == 0);
	err = chmod(modpath, S_IRUSR | S_IWUSR | S_IXUSR);
	CU_ASSERT(err == 0);

	err = semanage_store_access_check();
	CU_ASSERT(err == SEMANAGE_CAN_WRITE);
}

/* Tests the semanage_get_lock functions in semanage_store.c
 */
void test_semanage_get_lock(void)
{
	int err;

	/* attempt to get an active lock */
	err = semanage_get_active_lock(sh);
	CU_ASSERT(err == 0);

	/* attempt to get the lock again */
	err = semanage_get_active_lock(sh);
	CU_ASSERT(err == 0);

	/* attempt to release the active lock */
	semanage_release_active_lock(sh);

	/* attempt to get an active lock */
	err = semanage_get_active_lock(sh);
	CU_ASSERT(err == 0);

	/* attempt to release the active lock */
	semanage_release_active_lock(sh);

	/* attempt to get a trans lock */
	err = semanage_get_trans_lock(sh);
	CU_ASSERT(err == 0);

	/* attempt to get the lock again */
	err = semanage_get_trans_lock(sh);
	CU_ASSERT(err == 0);

	/* attempt to release the trans lock */
	semanage_release_trans_lock(sh);

	/* attempt to get a trans lock */
	err = semanage_get_trans_lock(sh);
	CU_ASSERT(err == 0);

	/* attempt to release the trans lock */
	semanage_release_trans_lock(sh);

	/* remove the lock files */
	err = remove(readlockpath);
	CU_ASSERT(err == 0);
	err = remove(translockpath);
	CU_ASSERT(err == 0);
}

/* Tests the semanage_nc_sort function in semanage_store.c
 */
void test_semanage_nc_sort(void)
{
	char *source_buf, *sorted_buf = NULL, *good_buf, *bad_buf;
	size_t source_buf_len, sorted_buf_len, good_buf_len, bad_buf_len;
	int sourcefd, goodfd, badfd, err;
	struct stat sb;

	/* open source file */
	sourcefd = open("nc_sort_unsorted", O_RDONLY);
	if (sourcefd < 0) {
		CU_FAIL("Missing nc_sort_unsorted test file.");
		return;
	}
	fstat(sourcefd, &sb);
	source_buf_len = sb.st_size;
	source_buf =
	    (char *)mmap(NULL, source_buf_len, PROT_READ, MAP_PRIVATE, sourcefd,
			 0);

	/* open good result file */
	goodfd = open("nc_sort_sorted", O_RDONLY);
	if (goodfd < 0) {
		CU_FAIL("Missing nc_sort_sorted test file.");
		goto out2;
	}
	fstat(goodfd, &sb);
	good_buf_len = sb.st_size;
	good_buf =
	    (char *)mmap(NULL, good_buf_len, PROT_READ, MAP_PRIVATE, goodfd, 0);

	/* open malformed source file (missing priorities) */
	badfd = open("nc_sort_malformed", O_RDONLY);
	if (badfd < 0) {
		CU_FAIL("Missing nc_sort_malformed test file.");
		goto out1;
	}
	fstat(badfd, &sb);
	bad_buf_len = sb.st_size;
	bad_buf =
	    (char *)mmap(NULL, bad_buf_len, PROT_READ, MAP_PRIVATE, badfd, 0);

	/* sort test file */
	err =
	    semanage_nc_sort(sh, source_buf, source_buf_len, &sorted_buf,
			     &sorted_buf_len);
	CU_ASSERT_FALSE(err);
	CU_ASSERT_STRING_EQUAL(sorted_buf, good_buf);

	/* reset for reuse in next test */
	free(sorted_buf);
	sorted_buf = NULL;

	/* sort malformed source file */
	err =
	    semanage_nc_sort(sh, bad_buf, bad_buf_len, &sorted_buf,
			     &sorted_buf_len);
	CU_ASSERT_EQUAL(err, -1);

	free(sorted_buf);

	munmap(bad_buf, bad_buf_len);
	close(badfd);
      out1:
	munmap(good_buf, good_buf_len);
	close(goodfd);
      out2:
	munmap(source_buf, source_buf_len);
	close(sourcefd);
}
