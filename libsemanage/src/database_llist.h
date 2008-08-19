/* Copyright (C) 2005 Red Hat, Inc. */

#ifndef _SEMANAGE_DATABASE_LLIST_INTERNAL_H_
#define _SEMANAGE_DATABASE_LLIST_INTERNAL_H_

#include "database.h"
#include "handle.h"

/* Representation of the database once loaded in memory */
typedef struct cache_entry {
	record_t *data;
	struct cache_entry *prev;
	struct cache_entry *next;
} cache_entry_t;

/* LLIST dbase */
typedef struct dbase_llist {

	/* Method tables */
	record_table_t *rtable;
	dbase_table_t *dtable;

	/* In-memory representation (cache) */
	cache_entry_t *cache;
	cache_entry_t *cache_tail;

	unsigned int cache_sz;
	int cache_serial;
	int modified;
} dbase_llist_t;

/* Helpers for internal use only */

static inline void dbase_llist_cache_init(dbase_llist_t * dbase)
{

	dbase->cache = NULL;
	dbase->cache_tail = NULL;
	dbase->cache_sz = 0;
	dbase->cache_serial = -1;
	dbase->modified = 0;
}

static inline void dbase_llist_init(dbase_llist_t * dbase,
				    record_table_t * rtable,
				    dbase_table_t * dtable)
{

	dbase->rtable = rtable;
	dbase->dtable = dtable;
	dbase_llist_cache_init(dbase);
}

extern int dbase_llist_cache_prepend(semanage_handle_t * handle,
				     dbase_llist_t * dbase,
				     const record_t * data);

extern int dbase_llist_needs_resync(semanage_handle_t * handle,
				    dbase_llist_t * dbase);

extern int dbase_llist_set_serial(semanage_handle_t * handle,
				  dbase_llist_t * dbase);

static inline void dbase_llist_set_modified(dbase_llist_t * dbase, int status)
{
	dbase->modified = status;
}

/* LLIST - cache/transactions */
extern void dbase_llist_drop_cache(dbase_llist_t * dbase);

static inline int dbase_llist_is_modified(dbase_llist_t * dbase)
{

	return dbase->modified;
}

/* LLIST - polymorphism */
static inline record_table_t *dbase_llist_get_rtable(dbase_llist_t * dbase)
{
	return dbase->rtable;
}

/* LLIST - dbase API */
extern int dbase_llist_exists(semanage_handle_t * handle,
			      dbase_llist_t * dbase,
			      const record_key_t * key, int *response);

extern int dbase_llist_add(semanage_handle_t * handle,
			   dbase_llist_t * dbase,
			   const record_key_t * key, const record_t * data);

extern int dbase_llist_set(semanage_handle_t * handle,
			   dbase_llist_t * dbase,
			   const record_key_t * key, const record_t * data);

extern int dbase_llist_modify(semanage_handle_t * handle,
			      dbase_llist_t * dbase,
			      const record_key_t * key, const record_t * data);

extern int dbase_llist_count(semanage_handle_t * handle,
			     dbase_llist_t * dbase, unsigned int *response);

extern int dbase_llist_query(semanage_handle_t * handle,
			     dbase_llist_t * dbase,
			     const record_key_t * key, record_t ** response);

extern int dbase_llist_iterate(semanage_handle_t * handle,
			       dbase_llist_t * dbase,
			       int (*fn) (const record_t * record,
					  void *fn_arg), void *arg);

extern int dbase_llist_del(semanage_handle_t * handle,
			   dbase_llist_t * dbase, const record_key_t * key);

extern int dbase_llist_clear(semanage_handle_t * handle, dbase_llist_t * dbase);

extern int dbase_llist_list(semanage_handle_t * handle,
			    dbase_llist_t * dbase,
			    record_t *** records, unsigned int *count);

#endif
