/* Copyright (C) 2005 Red Hat, Inc. */

#include <stdlib.h>
#include "policy.h"
#include "handle.h"
#include "database.h"
#include "modules.h"
#include "debug.h"

/* Powers of two only */
#define MODE_SET    1
#define MODE_MODIFY 2
#define MODE_SORT   4

static int clear_obsolete(semanage_handle_t * handle,
			  record_t ** records,
			  unsigned int nrecords,
			  dbase_config_t * src, dbase_config_t * dst)
{

	record_key_t *key = NULL;
	unsigned int i;

	const dbase_table_t *src_dtable = src->dtable;
	const dbase_table_t *dst_dtable = dst->dtable;
	const record_table_t *rtable = src_dtable->get_rtable(src->dbase);

	for (i = 0; i < nrecords; i++) {
		int exists;

		if (rtable->key_extract(handle, records[i], &key) < 0)
			goto err;

		if (dst_dtable->exists(handle, dst->dbase, key, &exists) < 0)
			goto err;

		if (!exists) {
			if (src_dtable->del(handle, src->dbase, key) < 0)
				goto err;

			rtable->free(records[i]);
			records[i] = NULL;

			/* FIXME: notice to user */
			/* INFO(handle, "boolean %s is obsolete, unsetting configured value..."); */
		}

		rtable->key_free(key);
	}

	return STATUS_SUCCESS;

      err:
	/* FIXME: handle error */
	rtable->key_free(key);
	return STATUS_ERR;
}

static int load_records(semanage_handle_t * handle,
			dbase_config_t * dst,
			record_t ** records, unsigned int nrecords, int mode)
{

	unsigned int i;
	record_key_t *rkey = NULL;

	dbase_t *dbase = dst->dbase;
	const dbase_table_t *dtable = dst->dtable;
	const record_table_t *rtable = dtable->get_rtable(dbase);

	for (i = 0; i < nrecords; i++) {

		/* Possibly obsoleted */
		if (!records[i])
			continue;

		if (rtable->key_extract(handle, records[i], &rkey) < 0)
			goto err;

		if (mode & MODE_SET &&
		    dtable->set(handle, dbase, rkey, records[i]) < 0)
			goto err;

		else if (mode & MODE_MODIFY &&
			 dtable->modify(handle, dbase, rkey, records[i]) < 0)
			goto err;

		rtable->key_free(rkey);
	}

	return STATUS_SUCCESS;

      err:
	/* FIXME: handle error */
	rtable->key_free(rkey);
	return STATUS_ERR;
}

typedef struct load_table {
	dbase_config_t *src;
	dbase_config_t *dst;
	int mode;
} load_table_t;

/* This function must be called AFTER all modules are loaded.
 * Modules could be represented as a database, in which case
 * they should be loaded at the beginning of this function */

int semanage_base_merge_components(semanage_handle_t * handle)
{

	unsigned int i, j;
	int rc = STATUS_SUCCESS;

	/* Order is important here - change things carefully.
	 * System components first, local next. Verify runs with
	 * mutual dependencies are ran after everything is merged */
	const load_table_t components[] = {

		{semanage_user_base_dbase_local(handle),
		 semanage_user_base_dbase_policy(handle), MODE_MODIFY},

		{semanage_user_extra_dbase_local(handle),
		 semanage_user_extra_dbase_policy(handle), MODE_MODIFY},

		{semanage_port_dbase_local(handle),
		 semanage_port_dbase_policy(handle), MODE_MODIFY},

		{semanage_iface_dbase_local(handle),
		 semanage_iface_dbase_policy(handle), MODE_MODIFY},

		{semanage_bool_dbase_local(handle),
		 semanage_bool_dbase_policy(handle), MODE_SET},

		{semanage_seuser_dbase_local(handle),
		 semanage_seuser_dbase_policy(handle), MODE_MODIFY},

		{semanage_node_dbase_local(handle),
		 semanage_node_dbase_policy(handle), MODE_MODIFY | MODE_SORT},

		{semanage_ibpkey_dbase_local(handle),
		 semanage_ibpkey_dbase_policy(handle), MODE_MODIFY},

		{semanage_ibendport_dbase_local(handle),
		 semanage_ibendport_dbase_policy(handle), MODE_MODIFY},
	};
	const unsigned int CCOUNT = sizeof(components) / sizeof(components[0]);

	/* Merge components into policy (and validate) */
	for (i = 0; i < CCOUNT; i++) {
		record_t **records = NULL;
		unsigned int nrecords = 0;

		dbase_config_t *src = components[i].src;
		dbase_config_t *dst = components[i].dst;
		int mode = components[i].mode;
		const record_table_t *rtable = src->dtable->get_rtable(src->dbase);

		/* Must invoke cache function first */
		if (src->dtable->cache(handle, src->dbase) < 0)
			goto err;
		if (dst->dtable->cache(handle, dst->dbase) < 0)
			goto err;

		/* List all records */
		if (src->dtable->list(handle, src->dbase,
				      &records, &nrecords) < 0)
			goto err;

		/* Sort records on MODE_SORT */
		if ((mode & MODE_SORT) && nrecords > 1) {
			qsort(records, nrecords, sizeof(record_t *), rtable->compare2_qsort);
		}

		/* Clear obsolete ones for MODE_SET */
		if (mode & MODE_SET &&
		    clear_obsolete(handle, records, nrecords, src, dst) < 0) {
			rc = STATUS_ERR;
			goto dbase_exit;
		}

		/* Load records */
		if (load_records(handle, dst, records, nrecords, mode) < 0) {

			rc = STATUS_ERR;
			goto dbase_exit;
		}

		/* Cleanup */
	      dbase_exit:
		for (j = 0; j < nrecords; j++)
			rtable->free(records[j]);
		free(records);

		/* Abort on error */
		if (rc < 0)
			goto err;
	}

	return rc;

      err:
	ERR(handle, "could not merge local modifications into policy");
	return STATUS_ERR;
}

int semanage_commit_components(semanage_handle_t * handle)
{

	int i;
	const dbase_config_t *components[] = {
		semanage_iface_dbase_local(handle),
		semanage_bool_dbase_local(handle),
		semanage_user_base_dbase_local(handle),
		semanage_user_extra_dbase_local(handle),
		semanage_user_extra_dbase_policy(handle),
		semanage_port_dbase_local(handle),
		semanage_fcontext_dbase_local(handle),
		semanage_fcontext_dbase_policy(handle),
		semanage_seuser_dbase_local(handle),
		semanage_seuser_dbase_policy(handle),
		semanage_bool_dbase_active(handle),
		semanage_node_dbase_local(handle),
		semanage_ibpkey_dbase_local(handle),
		semanage_ibendport_dbase_local(handle),
	};
	const int CCOUNT = sizeof(components) / sizeof(components[0]);

	for (i = 0; i < CCOUNT; i++) {
		/* Flush to disk */
		if (components[i]->dtable->flush(handle, components[i]->dbase) <
		    0)
			goto err;
	}

	return STATUS_SUCCESS;

      err:
	ERR(handle, "could not commit local/active modifications");

	for (i = 0; i < CCOUNT; i++)
		components[i]->dtable->drop_cache(components[i]->dbase);
	return STATUS_ERR;
}
