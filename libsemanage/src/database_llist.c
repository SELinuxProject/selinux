/* Copyright (C) 2005 Red Hat, Inc. */

/* Object: dbase_llist_t (Linked List)
 * Partially Implements: dbase_t (Database)
 */

struct dbase_llist;
typedef struct dbase_llist dbase_t;
#define DBASE_DEFINED

#include <stdlib.h>
#include "debug.h"
#include "handle.h"
#include "database_llist.h"

int dbase_llist_needs_resync(semanage_handle_t * handle, dbase_llist_t * dbase)
{

	int cache_serial;

	if (dbase->cache_serial < 0)
		return 1;

	cache_serial = handle->funcs->get_serial(handle);
	if (cache_serial < 0)
		return 1;

	if (cache_serial != dbase->cache_serial) {
		dbase_llist_drop_cache(dbase);
		dbase->cache_serial = -1;
		return 1;
	}
	return 0;
}

/* Helper for adding records to the cache */
int dbase_llist_cache_prepend(semanage_handle_t * handle,
			      dbase_llist_t * dbase, const record_t * data)
{

	/* Initialize */
	cache_entry_t *entry = (cache_entry_t *) malloc(sizeof(cache_entry_t));
	if (entry == NULL)
		goto omem;

	if (dbase->rtable->clone(handle, data, &entry->data) < 0)
		goto err;

	entry->prev = NULL;
	entry->next = dbase->cache;

	/* Link */
	if (dbase->cache != NULL)
		dbase->cache->prev = entry;
	if (dbase->cache_tail == NULL)
		dbase->cache_tail = entry;
	dbase->cache = entry;
	dbase->cache_sz++;
	return STATUS_SUCCESS;

      omem:
	ERR(handle, "out of memory");

      err:
	ERR(handle, "could not cache record");
	free(entry);
	return STATUS_ERR;
}

void dbase_llist_drop_cache(dbase_llist_t * dbase)
{

	if (dbase->cache_serial < 0)
		return;

	cache_entry_t *prev, *ptr = dbase->cache;
	while (ptr != NULL) {
		prev = ptr;
		ptr = ptr->next;
		dbase->rtable->free(prev->data);
		free(prev);
	}

	dbase->cache_serial = -1;
	dbase->modified = 0;
}

int dbase_llist_set_serial(semanage_handle_t * handle, dbase_llist_t * dbase)
{

	int cache_serial = handle->funcs->get_serial(handle);
	if (cache_serial < 0) {
		ERR(handle, "could not update cache serial");
		return STATUS_ERR;
	}

	dbase->cache_serial = cache_serial;
	return STATUS_SUCCESS;
}

/* Helper for finding records in the cache */
static int dbase_llist_cache_locate(semanage_handle_t * handle,
				    dbase_llist_t * dbase,
				    const record_key_t * key,
				    cache_entry_t ** entry)
{

	cache_entry_t *ptr;

	/* Implemented in parent */
	if (dbase->dtable->cache(handle, dbase) < 0)
		goto err;

	for (ptr = dbase->cache; ptr != NULL; ptr = ptr->next) {
		if (!dbase->rtable->compare(ptr->data, key)) {
			*entry = ptr;
			return STATUS_SUCCESS;
		}
	}

	return STATUS_NODATA;

      err:
	ERR(handle, "could not complete cache lookup");
	return STATUS_ERR;
}

int dbase_llist_exists(semanage_handle_t * handle,
		       dbase_llist_t * dbase,
		       const record_key_t * key, int *response)
{

	cache_entry_t *entry;
	int status;

	status = dbase_llist_cache_locate(handle, dbase, key, &entry);
	if (status < 0)
		goto err;

	*response = (status != STATUS_NODATA);
	return STATUS_SUCCESS;

      err:
	ERR(handle, "could not check if record exists");
	return STATUS_ERR;
}

int dbase_llist_add(semanage_handle_t * handle,
		    dbase_llist_t * dbase,
		    const record_key_t * key __attribute__ ((unused)),
			 const record_t * data)
{

	if (dbase_llist_cache_prepend(handle, dbase, data) < 0)
		goto err;

	dbase->modified = 1;
	return STATUS_SUCCESS;

      err:
	ERR(handle, "could not add record to the database");
	return STATUS_ERR;
}

int dbase_llist_set(semanage_handle_t * handle,
		    dbase_llist_t * dbase,
		    const record_key_t * key, const record_t * data)
{

	cache_entry_t *entry;
	int status;

	status = dbase_llist_cache_locate(handle, dbase, key, &entry);
	if (status < 0)
		goto err;
	if (status == STATUS_NODATA) {
		ERR(handle, "record not found in the database");
		goto err;
	} else {
		dbase->rtable->free(entry->data);
		if (dbase->rtable->clone(handle, data, &entry->data) < 0)
			goto err;
	}

	dbase->modified = 1;
	return STATUS_SUCCESS;

      err:
	ERR(handle, "could not set record value");
	return STATUS_ERR;
}

int dbase_llist_modify(semanage_handle_t * handle,
		       dbase_llist_t * dbase,
		       const record_key_t * key, const record_t * data)
{

	cache_entry_t *entry;
	int status;

	status = dbase_llist_cache_locate(handle, dbase, key, &entry);
	if (status < 0)
		goto err;
	if (status == STATUS_NODATA) {
		if (dbase_llist_cache_prepend(handle, dbase, data) < 0)
			goto err;
	} else {
		dbase->rtable->free(entry->data);
		if (dbase->rtable->clone(handle, data, &entry->data) < 0)
			goto err;
	}

	dbase->modified = 1;
	return STATUS_SUCCESS;

      err:
	ERR(handle, "could not modify record value");
	return STATUS_ERR;
}

 int dbase_llist_count(semanage_handle_t * handle __attribute__ ((unused)),
			     dbase_llist_t * dbase, unsigned int *response)
{

	*response = dbase->cache_sz;
	return STATUS_SUCCESS;
}

int dbase_llist_query(semanage_handle_t * handle,
		      dbase_llist_t * dbase,
		      const record_key_t * key, record_t ** response)
{

	cache_entry_t *entry;
	int status;

	status = dbase_llist_cache_locate(handle, dbase, key, &entry);
	if (status < 0 || status == STATUS_NODATA)
		goto err;

	if (dbase->rtable->clone(handle, entry->data, response) < 0)
		goto err;

	return STATUS_SUCCESS;

      err:
	ERR(handle, "could not query record value");
	return STATUS_ERR;
}

int dbase_llist_iterate(semanage_handle_t * handle,
			dbase_llist_t * dbase,
			int (*fn) (const record_t * record,
				   void *fn_arg), void *arg)
{

	int rc;
	cache_entry_t *ptr;

	for (ptr = dbase->cache_tail; ptr != NULL; ptr = ptr->prev) {

		rc = fn(ptr->data, arg);
		if (rc < 0)
			goto err;

		else if (rc > 0)
			break;
	}

	return STATUS_SUCCESS;

      err:
	ERR(handle, "could not iterate over records");
	return STATUS_ERR;
}

int dbase_llist_del(semanage_handle_t * handle __attribute__ ((unused)),
		    dbase_llist_t * dbase, const record_key_t * key)
{

	cache_entry_t *ptr, *prev = NULL;

	for (ptr = dbase->cache; ptr != NULL; ptr = ptr->next) {
		if (!dbase->rtable->compare(ptr->data, key)) {
			if (prev != NULL)
				prev->next = ptr->next;
			else
				dbase->cache = ptr->next;

			if (ptr->next != NULL)
				ptr->next->prev = ptr->prev;
			else
				dbase->cache_tail = ptr->prev;

			dbase->rtable->free(ptr->data);
			dbase->cache_sz--;
			free(ptr);
			dbase->modified = 1;
			return STATUS_SUCCESS;
		} else
			prev = ptr;
	}

	return STATUS_SUCCESS;
}

int dbase_llist_clear(semanage_handle_t * handle, dbase_llist_t * dbase)
{

	int old_serial = dbase->cache_serial;

	if (dbase_llist_set_serial(handle, dbase) < 0) {
		ERR(handle, "could not set serial of cleared dbase");
		return STATUS_ERR;
	}

	if (old_serial >= 0) {
		cache_entry_t *prev, *ptr = dbase->cache;
		while (ptr != NULL) {
			prev = ptr;
			ptr = ptr->next;
			dbase->rtable->free(prev->data);
			free(prev);
		}
	}

	dbase->cache = NULL;
	dbase->cache_tail = NULL;
	dbase->cache_sz = 0;
	dbase->modified = 1;
	return STATUS_SUCCESS;
}

int dbase_llist_list(semanage_handle_t * handle,
		     dbase_llist_t * dbase,
		     record_t *** records, unsigned int *count)
{

	cache_entry_t *ptr;
	record_t **tmp_records = NULL;
	unsigned int tmp_count;
	int i = 0;

	tmp_count = dbase->cache_sz;
	if (tmp_count > 0) {
		tmp_records = (record_t **)
		    calloc(tmp_count, sizeof(record_t *));

		if (tmp_records == NULL)
			goto omem;

		for (ptr = dbase->cache_tail; ptr != NULL; ptr = ptr->prev) {
			if (dbase->rtable->clone(handle,
						 ptr->data,
						 &tmp_records[i]) < 0)
				goto err;
			i++;
		}
	}

	*records = tmp_records;
	*count = tmp_count;
	return STATUS_SUCCESS;

      omem:
	ERR(handle, "out of memory");

      err:
	if (tmp_records) {
		for (; i >= 0; i--)
			dbase->rtable->free(tmp_records[i]);
		free(tmp_records);
	}
	ERR(handle, "could not allocate record array");
	return STATUS_ERR;
}
