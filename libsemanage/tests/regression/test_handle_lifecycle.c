/* SPDX-License-Identifier: LGPL-2.1-or-later */
#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "handle.h"

static int commit_result;
static int disconnect_result;
static int commits;
static int disconnects;
static int drops;
static int begins;
static int backend_returned;

static int begin(semanage_handle_t *sh)
{
	assert(!sh->is_in_transaction);
	begins++;
	return 0;
}

static int commit(semanage_handle_t *sh)
{
	assert(sh->is_in_transaction);
	commits++;
	backend_returned = 1;
	errno = commit_result < 0 ? EIO : 0;
	return commit_result;
}

static void drop(dbase_t *db)
{
	assert(backend_returned);
	*(int *)db = 0;
	drops++;
	/* A cache destructor must not replace the commit error. */
	errno = EINVAL;
}

static int disconnect(semanage_handle_t *sh)
{
	int i;

	assert(sh->is_connected);
	disconnects++;
	for (i = 0; i < DBASE_COUNT; i++)
		free(sh->dbase[i].dbase);
	errno = disconnect_result < 0 ? EACCES : 0;
	return disconnect_result;
}

static const dbase_table_t table = { .drop_cache = drop };
static const struct semanage_policy_table funcs = {
	.begin_trans = begin,
	.commit = commit,
	.disconnect = disconnect,
};

static void check_commit(int result)
{
	semanage_handle_t sh = { .funcs = &funcs, .is_connected = 1 };
	int cached[DBASE_COUNT];
	int i;

	commits = drops = begins = backend_returned = 0;
	commit_result = result;
	for (i = 0; i < DBASE_COUNT; i++) {
		cached[i] = 20;
		sh.dbase[i].dbase = (dbase_t *)&cached[i];
		sh.dbase[i].dtable = &table;
	}
	/* No transaction: do not call the backend or discard any cache. */
	assert(semanage_commit(&sh) < 0);
	assert(commits == 0 && drops == 0);
	assert(semanage_begin_transaction(&sh) == 0);
	assert(semanage_begin_transaction(&sh) == 0 && begins == 1);
	assert(drops == 0);
	sh.modules_modified = 1;
	assert(semanage_commit(&sh) == result);
	assert(errno == (result < 0 ? EIO : 0));
	assert(!sh.is_in_transaction && !sh.modules_modified);
	assert(commits == 1 && drops == DBASE_COUNT);
	for (i = 0; i < DBASE_COUNT; i++)
		assert(cached[i] == 0);
	/* No intervening read: a new transaction must not inherit old records. */
	assert(semanage_begin_transaction(&sh) == 0 && begins == 2);
	for (i = 0; i < DBASE_COUNT; i++)
		assert(cached[i] == 0);
	printf("commit result %d: all caches dropped, immediate restart clean\n",
	       result);
}

static void check_disconnect(int result)
{
	semanage_handle_t sh = {
		.funcs = &funcs,
		.is_connected = 1,
		.is_in_transaction = 1,
		.modules_modified = 1,
	};
	int i;

	disconnects = 0;
	disconnect_result = result;
	for (i = 0; i < DBASE_COUNT; i++) {
		sh.dbase[i].dbase = malloc(1);
		assert(sh.dbase[i].dbase);
		sh.dbase[i].dtable = &table;
	}
	assert(semanage_disconnect(&sh) == result);
	assert(errno == (result < 0 ? EACCES : 0));
	assert(!semanage_is_connected(&sh));
	assert(!sh.is_in_transaction && !sh.modules_modified);
	for (i = 0; i < DBASE_COUNT; i++) {
		assert(!sh.dbase[i].dbase);
		assert(!sh.dbase[i].dtable);
	}
	assert(semanage_disconnect(&sh) == 0 && disconnects == 1);
	assert(semanage_begin_transaction(&sh) < 0);
	printf("disconnect result %d: state cleared, repeat did not free twice\n",
	       result);
}

int main(void)
{
	check_commit(-1);
	check_commit(8);
	check_disconnect(-1);
	check_disconnect(0);
	puts("Handle lifecycle tests passed.");
	return 0;
}
