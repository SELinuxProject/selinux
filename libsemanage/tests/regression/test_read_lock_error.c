/* SPDX-License-Identifier: LGPL-2.1-or-later */
#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include "handle.h"
#include "database.h"

static int fail_cache;
static int fail_lock;
static int acquires;
static int releases;

int semanage_get_active_lock(semanage_handle_t *sh)
{
	acquires++;
	if (fail_lock)
		return -1;
	sh->u.direct.activelock_file_fd = 42;
	return 0;
}

void semanage_release_active_lock(semanage_handle_t *sh)
{
	releases++;
	sh->u.direct.activelock_file_fd = -1;
}

/* Only the lock declarations from semanage_store.h are needed here. */
#define SEMANAGE_MODULE_STORE_H
#include "../../src/database.c"

static int cache(semanage_handle_t *sh, dbase_t *db)
{
	(void)sh;
	(void)db;
	if (fail_cache) {
		errno = EIO;
		return -1;
	}
	return 0;
}

static int count(semanage_handle_t *sh, dbase_t *db, unsigned int *out)
{
	(void)sh;
	(void)db;
	*out = 0;
	return 0;
}

static int serial(semanage_handle_t *sh)
{
	(void)sh;
	return 17;
}

int main(void)
{
	semanage_conf_t conf = { .store_type = SEMANAGE_CON_DIRECT };
	struct semanage_policy_table funcs = { .get_serial = serial };
	semanage_handle_t sh = { .conf = &conf, .funcs = &funcs };
	dbase_table_t table = { .cache = cache, .count = count };
	dbase_config_t db = { .dtable = &table };
	unsigned int n = 99;
	int rc;

	sh.u.direct.activelock_file_fd = -1;
	fail_cache = 1;
	rc = dbase_count(&sh, &db, &n);
	printf("cache failure: rc=%d acquired=%d released=%d retained_fd=%d\n",
	       rc, acquires, releases, sh.u.direct.activelock_file_fd);
	assert(rc < 0 && acquires == 1 && releases == 1);
	assert(sh.u.direct.activelock_file_fd == -1 && errno == EIO);

	sh.u.direct.activelock_file_fd = -1;
	acquires = releases = 0;
	fail_cache = 0;
	assert(dbase_count(&sh, &db, &n) == 17);
	assert(acquires == 1 && releases == 1);
	puts("success control: lock released");

	acquires = releases = 0;
	sh.is_in_transaction = 1;
	fail_cache = 1;
	assert(dbase_count(&sh, &db, &n) < 0);
	assert(acquires == 0 && releases == 0);
	puts("transaction control: no active lock acquired or released");

	sh.is_in_transaction = 0;
	fail_lock = 1;
	assert(dbase_count(&sh, &db, &n) < 0);
	assert(releases == 0);
	puts("acquisition-failure control: no release");
	return 0;
}
