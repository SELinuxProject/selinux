/* SPDX-License-Identifier: LGPL-2.1-or-later */
#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sepol/policydb.h>

typedef int record_t;
typedef int record_key_t;
typedef int record1_t;
typedef int record2_t;
#define DBASE_RECORD_DEFINED
#define DBASE_RECORD_JOIN_DEFINED

static int loads;
static int live_records;
static int serial_calls;
static int serial_error;
static int serial_failures;
static int current_serial = 7;

#if defined(TEST_POLICYDB)
static FILE *missing_file(const char *path, const char *mode)
{
	(void)path;
	(void)mode;
	loads++;
	errno = ENOENT;
	return NULL;
}

static void free_policy(sepol_policydb_t *policy)
{
	if (policy)
		live_records--;
	sepol_policydb_free(policy);
}

static int create_policy(sepol_policydb_t **policy)
{
	int rc = sepol_policydb_create(policy);

	if (rc == 0)
		live_records++;
	return rc;
}

#define fopen missing_file
#define sepol_policydb_create create_policy
#define sepol_policydb_free free_policy
#include "../../src/database_policydb.c"
#undef fopen
#undef sepol_policydb_create
#undef sepol_policydb_free
#elif defined(TEST_FILE)
#include "../../src/database_file.c"
#elif defined(TEST_JOIN)
#include "../../src/database_join.c"
#elif defined(TEST_ACTIVE)
#include "../../src/database_activedb.c"
#else
#error "Select a database backend"
#endif

static int serial(semanage_handle_t *handle)
{
	(void)handle;
	serial_calls++;
	if (serial_error && serial_failures) {
		if (serial_failures > 0)
			serial_failures--;
		errno = serial_error;
		return -1;
	}
	return current_serial;
}

static void message(void *arg, semanage_handle_t *handle, const char *fmt, ...)
{
	(void)arg;
	(void)handle;
	(void)fmt;
	/* Logging must not overwrite the serial lookup error. */
	errno = EINVAL;
}

#if !defined(TEST_POLICYDB)
static int create(semanage_handle_t *handle, int **record)
{
	(void)handle;
	*record = malloc(sizeof(**record));
	assert(*record);
	live_records++;
	return 0;
}

static int clone(semanage_handle_t *handle, const int *in, int **out)
{
	create(handle, out);
	**out = *in;
	return 0;
}

static void release(int *record)
{
	if (record)
		live_records--;
	free(record);
}

static const record_table_t records = {
	.create = create,
	.clone = clone,
	.free = release,
	.key_free = release,
};
#endif

#if defined(TEST_FILE)
static int parsed;

unsigned int semanage_ro_root_count(void)
{
	return 0;
}

const char *semanage_path(enum semanage_store_defs store,
			  enum semanage_sandbox_defs file)
{
	(void)store;
	(void)file;
	abort();
}

const char *semanage_path_read(enum semanage_store_defs store,
			       enum semanage_sandbox_defs file)
{
	return semanage_path(store, file);
}

int parse_init(semanage_handle_t *handle, const char *name, void *arg,
	       parse_info_t **info)
{
	(void)handle;
	(void)name;
	(void)arg;
	*info = calloc(1, sizeof(**info));
	assert(*info);
	loads++;
	parsed = 0;
	return 0;
}

int parse_open(semanage_handle_t *handle, parse_info_t *info)
{
	(void)handle;
	(void)info;
	return 0;
}

void parse_close(parse_info_t *info)
{
	(void)info;
}

void parse_release(parse_info_t *info)
{
	free(info);
}

static int parse(semanage_handle_t *handle, parse_info_t *info, int *record)
{
	(void)handle;
	(void)info;
	if (parsed++)
		return STATUS_NODATA;
	*record = 10;
	return 0;
}
#elif defined(TEST_JOIN) || defined(TEST_ACTIVE)
static int read_list(semanage_handle_t *handle, int ***out, unsigned int *count)
{
	int value = 10;

	*out = malloc(sizeof(**out));
	assert(*out);
	clone(handle, &value, &(*out)[0]);
	*count = 1;
	loads++;
	return 0;
}
#endif

#if defined(TEST_JOIN)
static int child_cache(semanage_handle_t *handle, dbase_t *dbase)
{
	(void)handle;
	(void)dbase;
	return 0;
}

static int child_list(semanage_handle_t *handle, dbase_t *dbase, int ***out,
		      unsigned int *count)
{
	if (dbase)
		return read_list(handle, out, count);
	*out = NULL;
	*count = 0;
	return 0;
}

static const record_table_t *child_records(dbase_t *dbase)
{
	(void)dbase;
	return &records;
}

static int join(semanage_handle_t *handle, const int *first, const int *second,
		int **out)
{
	assert(first && !second);
	return clone(handle, first, out);
}
#endif

static void run_case(int dirty, int error)
{
	struct semanage_policy_table funcs = { .get_serial = serial };
	semanage_handle_t handle = {
		.funcs = &funcs,
		.is_in_transaction = 1,
		.msg_callback = message,
	};
	int before, i;
#if defined(TEST_POLICYDB)
	dbase_policydb_t *db = NULL;
	sepol_policydb_t *saved;

	assert(dbase_policydb_init(&handle, "active", "tmp", NULL, NULL, &db) ==
	       0);
#define CACHE() dbase_policydb_cache(&handle, db)
#define RELEASE() dbase_policydb_release(db)
#define MODIFIED db->modified
#define SERIAL db->cache_serial
#elif defined(TEST_FILE)
	record_file_table_t files = { .parse = parse };
	dbase_file_t *db;

	assert(dbase_file_init(&handle, "active", "tmp", &records, &files,
			       &db) == 0);
#define CACHE() dbase_file_cache(&handle, db)
#define RELEASE() dbase_file_release(db)
#elif defined(TEST_JOIN)
	const dbase_table_t child_table = {
		.cache = child_cache,
		.list = child_list,
		.get_rtable = child_records,
	};
	dbase_config_t first = { .dtable = &child_table };
	dbase_config_t second = { .dtable = &child_table };
	record_join_table_t joins = { .join = join };
	dbase_join_t *db;

	/* A non-NULL child supplies one record; the other supplies an empty list. */
	first.dbase = (dbase_t *)&first;
	assert(dbase_join_init(&handle, &records, &joins, &first, &second,
			       &db) == 0);
#define CACHE() dbase_join_cache(&handle, db)
#define RELEASE() dbase_join_release(db)
#elif defined(TEST_ACTIVE)
	record_activedb_table_t active = { .read_list = read_list };
	dbase_activedb_t *db;

	assert(dbase_activedb_init(&handle, &records, &active, &db) == 0);
#define CACHE() dbase_activedb_cache(&handle, db)
#define RELEASE() dbase_activedb_release(db)
#endif
#if !defined(TEST_POLICYDB)
	cache_entry_t *saved;
#define MODIFIED db->llist.modified
#define SERIAL db->llist.cache_serial
#endif

	assert(live_records == 0);
	/* Failure during initial loading must leave an empty, retryable cache. */
	serial_error = error;
	serial_failures = 1;
	assert(CACHE() == -1);
	assert(live_records == 0 && SERIAL == -1 && MODIFIED == 0);
	serial_error = 0;
	assert(CACHE() == 0);
	assert(live_records == 1);
	MODIFIED = dirty;
#if defined(TEST_POLICYDB)
	saved = db->policydb;
#else
	saved = db->llist.cache;
	*saved->data = dirty ? 20 : 10;
#endif
	before = loads;
	serial_error = error;
	for (i = 0; i < 2; i++) {
		int calls = serial_calls;

		/* One-shot failure first, then a failure that persists until reset. */
		serial_failures = i ? -1 : 1;
		assert(CACHE() == -1);
		assert(errno == error);
		assert(serial_calls == calls + 1);
		assert(loads == before && live_records == 1);
		assert(MODIFIED == dirty && SERIAL == current_serial);
#if defined(TEST_POLICYDB)
		assert(db->policydb == saved);
#else
		assert(db->llist.cache == saved);
		assert(db->llist.cache_tail == saved &&
		       db->llist.cache_sz == 1);
		assert(*saved->data == (dirty ? 20 : 10));
#endif
	}
	serial_error = 0;
	assert(CACHE() == 0);
	assert(loads == before && MODIFIED == dirty && live_records == 1);

	/* A real serial change must still replace and release the old cache. */
	current_serial++;
	assert(CACHE() == 0);
	assert(loads == before + 1 && MODIFIED == 0 && live_records == 1);
	assert(SERIAL == current_serial);
#if !defined(TEST_POLICYDB)
	assert(*db->llist.cache->data == 10);
#else
	/* Attached policies belong to the caller and bypass serial lookups. */
	assert(create_policy(&saved) == 0);
	dbase_policydb_attach(db, saved);
	assert(live_records == 1);
	before = serial_calls;
	serial_error = error;
	serial_failures = -1;
	assert(CACHE() == 0 && serial_calls == before);
	assert(db->policydb == saved);
	dbase_policydb_detach(db);
#endif
	RELEASE();
#if defined(TEST_POLICYDB)
	assert(live_records == 1);
	free_policy(saved);
#endif
	assert(live_records == 0);
	printf("dirty=%d errno=%d: preserved on error, retry and resync passed\n",
	       dirty, error);
}

int main(void)
{
	const int errors[] = { EINTR, EIO, EMFILE };
	size_t i;
	int dirty;

	for (dirty = 0; dirty <= 1; dirty++)
		for (i = 0; i < sizeof(errors) / sizeof(errors[0]); i++)
			run_case(dirty, errors[i]);
	return 0;
}
