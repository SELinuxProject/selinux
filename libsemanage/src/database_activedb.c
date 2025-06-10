/* Copyright (C) 2005 Red Hat, Inc. */

/* Object: dbase_activedb_t (Active/Kernel)
 * Extends: dbase_llist_t (Linked List)
 * Implements: dbase_t (Database)
 */

struct dbase_activedb;
typedef struct dbase_activedb dbase_t;
#define DBASE_DEFINED

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "debug.h"
#include "handle.h"
#include "database_activedb.h"
#include "database_llist.h"

/* ACTIVEDB dbase */
struct dbase_activedb {

	/* Parent object - must always be
	 * the first field - here we are using
	 * a linked list to store the records */
	dbase_llist_t llist;

	/* ACTIVEDB extension */
	const record_activedb_table_t *ratable;
};

static int dbase_activedb_cache(semanage_handle_t * handle,
				dbase_activedb_t * dbase)
{

	const record_table_t *rtable = dbase_llist_get_rtable(&dbase->llist);
	const record_activedb_table_t *ratable = dbase->ratable;

	record_t **records = NULL;
	unsigned int rcount = 0;
	unsigned int i = 0;

	/* Already cached */
	if (!dbase_llist_needs_resync(handle, &dbase->llist))
		return STATUS_SUCCESS;

	/* Update cache serial */
	dbase_llist_cache_init(&dbase->llist);
	if (dbase_llist_set_serial(handle, &dbase->llist) < 0)
		goto err;

	/* Fetch the entire list */
	if (ratable->read_list(handle, &records, &rcount) < 0)
		goto err;

	/* Add records one by one */
	for (; i < rcount; i++) {
		if (dbase_llist_cache_prepend(handle, &dbase->llist, records[i])
		    < 0)
			goto err;
		rtable->free(records[i]);
	}

	free(records);
	return STATUS_SUCCESS;

      err:
	ERR(handle, "could not cache active database");
	for (; i < rcount; i++)
		rtable->free(records[i]);
	dbase_llist_drop_cache(&dbase->llist);
	free(records);
	return STATUS_ERR;
}

static int dbase_activedb_flush(semanage_handle_t * handle,
				dbase_activedb_t * dbase)
{

	const record_table_t *rtable = dbase_llist_get_rtable(&dbase->llist);
	const record_activedb_table_t *ratable = dbase->ratable;

	record_t **records = NULL;
	unsigned int rcount = 0;
	unsigned int i;

	/* Not cached, or not modified - flush is not necessary */
	if (!dbase_llist_is_modified(&dbase->llist))
		return STATUS_SUCCESS;

	/* Fetch list */
	if (dbase_llist_list(handle, &dbase->llist, &records, &rcount) < 0)
		goto err;

	/* Commit */
	if (ratable->commit_list(handle, records, rcount) < 0)
		goto err;

	for (i = 0; i < rcount; i++)
		rtable->free(records[i]);
	free(records);
	dbase_llist_set_modified(&dbase->llist, 0);
	return STATUS_SUCCESS;

      err:
	for (i = 0; i < rcount; i++)
		rtable->free(records[i]);
	free(records);
	ERR(handle, "could not flush active database");
	return STATUS_ERR;
}

int dbase_activedb_init(semanage_handle_t * handle,
			const record_table_t * rtable,
			const record_activedb_table_t * ratable,
			dbase_activedb_t ** dbase)
{

	dbase_activedb_t *tmp_dbase =
	    (dbase_activedb_t *) malloc(sizeof(dbase_activedb_t));

	if (!tmp_dbase)
		goto omem;

	tmp_dbase->ratable = ratable;
	dbase_llist_init(&tmp_dbase->llist, rtable, &SEMANAGE_ACTIVEDB_DTABLE);

	*dbase = tmp_dbase;

	return STATUS_SUCCESS;

      omem:
	ERR(handle, "out of memory, could not initialize active database");
	free(tmp_dbase);
	return STATUS_ERR;
}

/* Release dbase resources */
void dbase_activedb_release(dbase_activedb_t * dbase)
{

	if (!dbase)
		return;

	dbase_llist_drop_cache(&dbase->llist);
	free(dbase);
}

/* ACTIVEDB dbase - method table implementation */
const dbase_table_t SEMANAGE_ACTIVEDB_DTABLE = {

	/* Cache/Transactions */
	.cache = dbase_activedb_cache,
	.drop_cache = (void *)dbase_llist_drop_cache,
	.flush = dbase_activedb_flush,
	.is_modified = (void *)dbase_llist_is_modified,

	/* Database API */
	.iterate = (void *)dbase_llist_iterate,
	.exists = (void *)dbase_llist_exists,
	.list = (void *)dbase_llist_list,
	.add = (void *)dbase_llist_add,
	.set = (void *)dbase_llist_set,
	.del = (void *)dbase_llist_del,
	.clear = (void *)dbase_llist_clear,
	.modify = (void *)dbase_llist_modify,
	.query = (void *)dbase_llist_query,
	.count = (void *)dbase_llist_count,

	/* Polymorphism */
	.get_rtable = (void *)dbase_llist_get_rtable
};
