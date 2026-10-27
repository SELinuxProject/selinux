/* SPDX-License-Identifier: LGPL-2.1-or-later */
#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <semanage/semanage.h>

static int used_failed_list;
static int deleted;
static int cleaned_failed_list;
static int freed_user;
static int list_error = EIO;
static int referenced;
static semanage_seuser_t *sentinel_records[1];

static void probe_free(void *ptr)
{
	assert(ptr == sentinel_records);
	cleaned_failed_list++;
}

/* Compile the actual implementation; intercept only its dependencies. */
#define free probe_free
#include "../../src/users_local.c"
#undef free

int semanage_user_query(semanage_handle_t *sh, const semanage_user_key_t *key,
			semanage_user_t **out)
{
	(void)sh;
	(void)key;
	*out = (semanage_user_t *)1;
	return 0;
}

const char *semanage_user_get_name(const semanage_user_t *user)
{
	(void)user;
	return "user_u";
}

void semanage_user_free(semanage_user_t *user)
{
	(void)user;
	freed_user++;
}

int semanage_seuser_list_local(semanage_handle_t *sh, semanage_seuser_t ***out,
			       unsigned int *count)
{
	(void)sh;
	/* Fail without publishing output, as real cache/list failures do. */
	if (list_error) {
		errno = list_error;
		return -1;
	}
	*out = sentinel_records;
	*count = 1;
	return 0;
}

const char *semanage_seuser_get_sename(const semanage_seuser_t *record)
{
	(void)record;
	used_failed_list++;
	return referenced ? "user_u" : "other_u";
}

const char *semanage_seuser_get_name(const semanage_seuser_t *record)
{
	(void)record;
	return "login";
}

void semanage_seuser_free(semanage_seuser_t *record)
{
	(void)record;
	cleaned_failed_list++;
}

int dbase_del(semanage_handle_t *sh, dbase_config_t *db,
	      const record_key_t *key)
{
	(void)sh;
	(void)db;
	(void)key;
	deleted++;
	return 0;
}

int dbase_modify(semanage_handle_t *sh, dbase_config_t *db,
		 const record_key_t *key, const record_t *data)
{
	(void)sh;
	(void)db;
	(void)key;
	(void)data;
	abort();
}

int dbase_query(semanage_handle_t *sh, dbase_config_t *db,
		const record_key_t *key, record_t **out)
{
	(void)sh;
	(void)db;
	(void)key;
	(void)out;
	abort();
}

int dbase_exists(semanage_handle_t *sh, dbase_config_t *db,
		 const record_key_t *key, int *out)
{
	(void)sh;
	(void)db;
	(void)key;
	(void)out;
	abort();
}

int dbase_count(semanage_handle_t *sh, dbase_config_t *db, unsigned int *out)
{
	(void)sh;
	(void)db;
	(void)out;
	abort();
}

int dbase_list(semanage_handle_t *sh, dbase_config_t *db, record_t ***out,
	       unsigned int *count)
{
	(void)sh;
	(void)db;
	(void)out;
	(void)count;
	abort();
}

int dbase_iterate(semanage_handle_t *sh, dbase_config_t *db,
		  int (*fn)(const record_t *, void *), void *arg)
{
	(void)sh;
	(void)db;
	(void)fn;
	(void)arg;
	abort();
}

int main(void)
{
	semanage_handle_t sh = { 0 };
	int rc = semanage_user_del_local(&sh, NULL);

	printf("list returned -1: delete rc=%d output_used=%d cleanup=%d deleted=%d\n",
	       rc, used_failed_list, cleaned_failed_list, deleted);
	assert(rc < 0 && errno == EIO && freed_user == 1);
	assert(used_failed_list == 0 && cleaned_failed_list == 0 &&
	       deleted == 0);
	list_error = ENOMEM;
	assert(semanage_user_del_local(&sh, NULL) < 0 && errno == ENOMEM);
	assert(freed_user == 2 && deleted == 0 && cleaned_failed_list == 0);
	list_error = 0;
	referenced = 1;
	assert(semanage_user_del_local(&sh, NULL) < 0 && errno == EINVAL);
	assert(deleted == 0 && freed_user == 3 && cleaned_failed_list == 2);
	referenced = 0;
	assert(semanage_user_del_local(&sh, NULL) == 0);
	assert(deleted == 1 && freed_user == 4 && cleaned_failed_list == 4);
	puts("User deletion error and success controls passed.");
	return 0;
}
