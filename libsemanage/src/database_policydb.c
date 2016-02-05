/* Copyright (C) 2005 Red Hat, Inc. */

/* Object: dbase_policydb_t (Policy)
 * Implements: dbase_t (Database)
 */

struct dbase_policydb;
typedef struct dbase_policydb dbase_t;
#define DBASE_DEFINED

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <errno.h>

#include <sepol/policydb.h>

#include "database_policydb.h"
#include "semanage_store.h"
#include "handle.h"
#include "debug.h"

/* POLICYDB dbase */
struct dbase_policydb {

        /* Backing path for read-only[0] and transaction[1] */
        const char *path[2];

	/* Base record table */
	record_table_t *rtable;

	/* Policy extensions */
	record_policydb_table_t *rptable;

	sepol_policydb_t *policydb;

	int cache_serial;
	int modified;
	int attached;
};

static void dbase_policydb_drop_cache(dbase_policydb_t * dbase)
{

	if (dbase->cache_serial >= 0) {
		sepol_policydb_free(dbase->policydb);
		dbase->cache_serial = -1;
		dbase->modified = 0;
	}
}

static int dbase_policydb_set_serial(semanage_handle_t * handle,
				     dbase_policydb_t * dbase)
{

	int cache_serial = handle->funcs->get_serial(handle);
	if (cache_serial < 0) {
		ERR(handle, "could not update cache serial");
		return STATUS_ERR;
	}

	dbase->cache_serial = cache_serial;
	return STATUS_SUCCESS;
}

static int dbase_policydb_needs_resync(semanage_handle_t * handle,
				       dbase_policydb_t * dbase)
{

	int cache_serial;

	if (dbase->cache_serial < 0)
		return 1;

	cache_serial = handle->funcs->get_serial(handle);
	if (cache_serial < 0)
		return 1;

	if (cache_serial != dbase->cache_serial) {
		dbase_policydb_drop_cache(dbase);
		dbase->cache_serial = -1;
		return 1;
	}
	return 0;
}

static int dbase_policydb_cache(semanage_handle_t * handle,
				dbase_policydb_t * dbase)
{

	FILE *fp = NULL;
	sepol_policydb_t *policydb = NULL;
	sepol_policy_file_t *pf = NULL;
	const char *fname = NULL;

	/* Check if cache is needed */
	if (dbase->attached)
		return STATUS_SUCCESS;

	if (!dbase_policydb_needs_resync(handle, dbase))
		return STATUS_SUCCESS;

	fname = dbase->path[handle->is_in_transaction];

	if (sepol_policydb_create(&policydb) < 0) {
		ERR(handle, "could not create policydb object");
		goto err;
	}

	/* Try opening file 
	 * ENOENT is not fatal - we just create an empty policydb */
	fp = fopen(fname, "rb");
	if (fp == NULL && errno != ENOENT) {
		ERR(handle, "could not open %s for reading: %s",
		    fname, strerror(errno));
		goto err;
	}

	/* If the file was opened successfully, read a policydb */
	if (fp != NULL) {
		__fsetlocking(fp, FSETLOCKING_BYCALLER);
		if (sepol_policy_file_create(&pf) < 0) {
			ERR(handle, "could not create policy file object");
			goto err;
		}

		sepol_policy_file_set_fp(pf, fp);
		sepol_policy_file_set_handle(pf, handle->sepolh);

		if (sepol_policydb_read(policydb, pf) < 0)
			goto err;

		sepol_policy_file_free(pf);
		fclose(fp);
		fp = NULL;
	}

	/* Update cache serial */
	if (dbase_policydb_set_serial(handle, dbase) < 0)
		goto err;

	/* Update the database policydb */
	dbase->policydb = policydb;
	return STATUS_SUCCESS;

      err:
	ERR(handle, "could not cache policy database");
	if (fp)
		fclose(fp);
	sepol_policydb_free(policydb);
	sepol_policy_file_free(pf);
	return STATUS_ERR;
}

static int dbase_policydb_flush(semanage_handle_t * handle
				__attribute__ ((unused)),
				dbase_policydb_t * dbase)
{

	if (!dbase->modified)
		return STATUS_SUCCESS;

	dbase->modified = 0;

	/* Stub */
	return STATUS_ERR;
}

/* Check if modified */
static int dbase_policydb_is_modified(dbase_policydb_t * dbase)
{

	return dbase->modified;
}

int dbase_policydb_init(semanage_handle_t * handle,
			const char *path_ro,
			const char *path_rw,
			record_table_t * rtable,
			record_policydb_table_t * rptable,
			dbase_policydb_t ** dbase)
{

	dbase_policydb_t *tmp_dbase =
	    (dbase_policydb_t *) malloc(sizeof(dbase_policydb_t));

	if (!tmp_dbase)
		goto omem;

	tmp_dbase->path[0] = path_ro;
	tmp_dbase->path[1] = path_rw;
	tmp_dbase->rtable = rtable;
	tmp_dbase->rptable = rptable;
	tmp_dbase->policydb = NULL;
	tmp_dbase->cache_serial = -1;
	tmp_dbase->modified = 0;
	tmp_dbase->attached = 0;
	*dbase = tmp_dbase;

	return STATUS_SUCCESS;

      omem:
	ERR(handle, "out of memory, could not initialize policy database");
	free(tmp_dbase);

	return STATUS_ERR;
}

/* Release dbase resources */
void dbase_policydb_release(dbase_policydb_t * dbase)
{

	dbase_policydb_drop_cache(dbase);
	free(dbase);
}

/* Attach to a shared policydb.
 * This implies drop_cache(),
 * and prevents flush() and drop_cache()
 * until detached. */
void dbase_policydb_attach(dbase_policydb_t * dbase,
			   sepol_policydb_t * policydb)
{

	dbase->attached = 1;
	dbase_policydb_drop_cache(dbase);
	dbase->policydb = policydb;
}

/* Detach from a shared policdb.
 * This implies drop_cache. */
void dbase_policydb_detach(dbase_policydb_t * dbase)
{

	dbase->attached = 0;
	dbase->modified = 0;
}

static int dbase_policydb_add(semanage_handle_t * handle,
			      dbase_policydb_t * dbase,
			      const record_key_t * key, const record_t * data)
{

	if (dbase->rptable->add(handle->sepolh, dbase->policydb, key, data) < 0)
		goto err;

	dbase->modified = 1;
	return STATUS_SUCCESS;

      err:
	ERR(handle, "could not add record to the database");
	return STATUS_ERR;
}

static int dbase_policydb_set(semanage_handle_t * handle,
			      dbase_policydb_t * dbase,
			      const record_key_t * key, const record_t * data)
{

	if (dbase->rptable->set(handle->sepolh, dbase->policydb, key, data) < 0)
		goto err;

	dbase->modified = 1;
	return STATUS_SUCCESS;

      err:
	ERR(handle, "could not set record value");
	return STATUS_ERR;
}

static int dbase_policydb_modify(semanage_handle_t * handle,
				 dbase_policydb_t * dbase,
				 const record_key_t * key,
				 const record_t * data)
{

	if (dbase->rptable->modify(handle->sepolh,
				   dbase->policydb, key, data) < 0)
		goto err;

	dbase->modified = 1;
	return STATUS_SUCCESS;

      err:
	ERR(handle, "could not modify record value");
	return STATUS_ERR;
}

static int dbase_policydb_del(semanage_handle_t * handle
				__attribute__ ((unused)),
			      dbase_policydb_t * dbase
				__attribute__ ((unused)),
			      const record_key_t * key
				__attribute__ ((unused)))
{

	/* Stub */
	return STATUS_ERR;
}

static int dbase_policydb_clear(semanage_handle_t * handle
				__attribute__ ((unused)),
				dbase_policydb_t * dbase
				__attribute__ ((unused)))
{

	/* Stub */
	return STATUS_ERR;
}

static int dbase_policydb_query(semanage_handle_t * handle,
				dbase_policydb_t * dbase,
				const record_key_t * key, record_t ** response)
{

	if (dbase->rptable->query(handle->sepolh,
				  dbase->policydb, key, response) < 0)
		goto err;

	return STATUS_SUCCESS;

      err:
	ERR(handle, "could not query record value");
	return STATUS_ERR;
}

static int dbase_policydb_exists(semanage_handle_t * handle,
				 dbase_policydb_t * dbase,
				 const record_key_t * key, int *response)
{

	if (dbase->rptable->exists(handle->sepolh,
				   dbase->policydb, key, response) < 0)
		goto err;

	return STATUS_SUCCESS;

      err:
	ERR(handle, "could not check if record exists");
	return STATUS_ERR;
}

static int dbase_policydb_count(semanage_handle_t * handle,
				dbase_policydb_t * dbase,
				unsigned int *response)
{

	if (dbase->rptable->count(handle->sepolh,
				  dbase->policydb, response) < 0)
		goto err;

	return STATUS_SUCCESS;

      err:
	ERR(handle, "could not count the database records");
	return STATUS_ERR;
}

static int dbase_policydb_iterate(semanage_handle_t * handle,
				  dbase_policydb_t * dbase,
				  int (*fn) (const record_t * record,
					     void *fn_arg), void *arg)
{

	if (dbase->rptable->iterate(handle->sepolh,
				    dbase->policydb, fn, arg) < 0)
		goto err;

	return STATUS_SUCCESS;

      err:
	ERR(handle, "could not iterate over records");
	return STATUS_ERR;
}

struct list_handler_arg {
	semanage_handle_t *handle;
	record_table_t *rtable;
	record_t **records;
	int pos;
};

static int list_handler(const record_t * record, void *varg)
{

	struct list_handler_arg *arg = (struct list_handler_arg *)varg;

	if (arg->rtable->clone(arg->handle, record, &arg->records[arg->pos]) <
	    0)
		return -1;
	arg->pos++;
	return 0;
}

static int dbase_policydb_list(semanage_handle_t * handle,
			       dbase_t * dbase,
			       record_t *** records, unsigned int *count)
{

	record_t **tmp_records = NULL;
	unsigned int tmp_count;
	struct list_handler_arg list_arg;
	list_arg.pos = 0;
	list_arg.rtable = dbase->rtable;
	list_arg.handle = handle;

	if (dbase->rptable->count(handle->sepolh,
				  dbase->policydb, &tmp_count) < 0)
		goto err;

	if (tmp_count > 0) {
		tmp_records = (record_t **)
		    calloc(tmp_count, sizeof(record_t *));

		if (tmp_records == NULL)
			goto omem;

		list_arg.records = tmp_records;

		if (dbase->rptable->iterate(handle->sepolh,
					    dbase->policydb, list_handler,
					    &list_arg) < 0) {
			ERR(handle, "list handler could not extract record");
			goto err;
		}
	}

	*records = tmp_records;
	*count = tmp_count;
	return STATUS_SUCCESS;

      omem:
	ERR(handle, "out of memory");

      err:
	if (tmp_records) {
		for (; list_arg.pos >= 0; list_arg.pos--)
			dbase->rtable->free(tmp_records[list_arg.pos]);
		free(tmp_records);
	}
	ERR(handle, "could not list records");
	return STATUS_ERR;
}

static record_table_t *dbase_policydb_get_rtable(dbase_policydb_t * dbase)
{

	return dbase->rtable;
}

/* POLICYDB dbase - method table implementation */
dbase_table_t SEMANAGE_POLICYDB_DTABLE = {

	/* Cache/Transactions */
	.cache = dbase_policydb_cache,
	.drop_cache = dbase_policydb_drop_cache,
	.flush = dbase_policydb_flush,
	.is_modified = dbase_policydb_is_modified,

	/* Database Functionality */
	.iterate = dbase_policydb_iterate,
	.exists = dbase_policydb_exists,
	.list = dbase_policydb_list,
	.add = dbase_policydb_add,
	.set = dbase_policydb_set,
	.del = dbase_policydb_del,
	.clear = dbase_policydb_clear,
	.modify = dbase_policydb_modify,
	.query = dbase_policydb_query,
	.count = dbase_policydb_count,

	/* Polymorphism */
	.get_rtable = dbase_policydb_get_rtable
};
