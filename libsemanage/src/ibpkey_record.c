/* Copyright (C) 2017 Mellanox Technologies Inc. */

/* Object: semanage_ibpkey_t (Infiniband Pkey)
 * Object: semanage_ibpkey_key_t (Infiniband Pkey Key)
 * Implements: record_t (Database Record)
 * Implements: record_key_t (Database Record Key)
 */

#include <sepol/context_record.h>
#include <sepol/ibpkey_record.h>

typedef sepol_context_t semanage_context_t;
typedef sepol_ibpkey_t semanage_ibpkey_t;
typedef sepol_ibpkey_key_t semanage_ibpkey_key_t;
#define _SEMANAGE_IBPKEY_DEFINED_
#define _SEMANAGE_CONTEXT_DEFINED_

typedef semanage_ibpkey_t record_t;
typedef semanage_ibpkey_key_t record_key_t;
#define DBASE_RECORD_DEFINED

#include "ibpkey_internal.h"
#include "handle.h"
#include "database.h"

int semanage_ibpkey_compare(const semanage_ibpkey_t *ibpkey,
			    const semanage_ibpkey_key_t *key)
{
	return sepol_ibpkey_compare(ibpkey, key);
}


int semanage_ibpkey_compare2(const semanage_ibpkey_t *ibpkey,
			     const semanage_ibpkey_t *ibpkey2)
{
	return sepol_ibpkey_compare2(ibpkey, ibpkey2);
}


 int semanage_ibpkey_compare2_qsort(const void *p1, const void *p2)
{
	const semanage_ibpkey_t *const *ibpkey1 = p1;
	const semanage_ibpkey_t *const *ibpkey2 = p2;

	return sepol_ibpkey_compare2(*ibpkey1, *ibpkey2);
}

int semanage_ibpkey_key_create(semanage_handle_t *handle,
			       const char *subnet_prefix,
			       int low, int high,
			       semanage_ibpkey_key_t **key_ptr)
{
	return sepol_ibpkey_key_create(handle->sepolh, subnet_prefix, low, high, key_ptr);
}

int semanage_ibpkey_key_extract(semanage_handle_t *handle,
				const semanage_ibpkey_t *ibpkey,
				semanage_ibpkey_key_t **key_ptr)
{
	return sepol_ibpkey_key_extract(handle->sepolh, ibpkey, key_ptr);
}


void semanage_ibpkey_key_free(semanage_ibpkey_key_t *key)
{
	sepol_ibpkey_key_free(key);
}


int semanage_ibpkey_get_subnet_prefix(semanage_handle_t *handle,
				      const semanage_ibpkey_t *ibpkey,
				      char **subnet_prefix_ptr)
{
	return sepol_ibpkey_get_subnet_prefix(handle->sepolh, ibpkey, subnet_prefix_ptr);
}


uint64_t semanage_ibpkey_get_subnet_prefix_bytes(const semanage_ibpkey_t *ibpkey)
{
	return sepol_ibpkey_get_subnet_prefix_bytes(ibpkey);
}


int semanage_ibpkey_set_subnet_prefix(semanage_handle_t *handle,
				      semanage_ibpkey_t *ibpkey,
				      const char *subnet_prefix)
{
	return sepol_ibpkey_set_subnet_prefix(handle->sepolh, ibpkey, subnet_prefix);
}


void semanage_ibpkey_set_subnet_prefix_bytes(semanage_ibpkey_t *ibpkey,
					     uint64_t subnet_prefix)
{
	return sepol_ibpkey_set_subnet_prefix_bytes(ibpkey, subnet_prefix);
}


int semanage_ibpkey_get_low(const semanage_ibpkey_t *ibpkey)
{
	return sepol_ibpkey_get_low(ibpkey);
}


int semanage_ibpkey_get_high(const semanage_ibpkey_t *ibpkey)
{
	return sepol_ibpkey_get_high(ibpkey);
}


void semanage_ibpkey_set_pkey(semanage_ibpkey_t *ibpkey, int ibpkey_num)
{
	sepol_ibpkey_set_pkey(ibpkey, ibpkey_num);
}


void semanage_ibpkey_set_range(semanage_ibpkey_t *ibpkey, int low, int high)
{
	sepol_ibpkey_set_range(ibpkey, low, high);
}


semanage_context_t *semanage_ibpkey_get_con(const semanage_ibpkey_t *ibpkey)
{
	return sepol_ibpkey_get_con(ibpkey);
}


int semanage_ibpkey_set_con(semanage_handle_t *handle,
			    semanage_ibpkey_t *ibpkey, semanage_context_t *con)
{
	return sepol_ibpkey_set_con(handle->sepolh, ibpkey, con);
}


int semanage_ibpkey_create(semanage_handle_t *handle,
			   semanage_ibpkey_t **ibpkey_ptr)
{
	return sepol_ibpkey_create(handle->sepolh, ibpkey_ptr);
}


int semanage_ibpkey_clone(semanage_handle_t *handle,
			  const semanage_ibpkey_t *ibpkey,
			  semanage_ibpkey_t **ibpkey_ptr)
{
	return sepol_ibpkey_clone(handle->sepolh, ibpkey, ibpkey_ptr);
}


void semanage_ibpkey_free(semanage_ibpkey_t *ibpkey)
{
	sepol_ibpkey_free(ibpkey);
}


/* key base functions */
const record_table_t SEMANAGE_IBPKEY_RTABLE = {
	.create = semanage_ibpkey_create,
	.key_extract = semanage_ibpkey_key_extract,
	.key_free = semanage_ibpkey_key_free,
	.clone = semanage_ibpkey_clone,
	.compare = semanage_ibpkey_compare,
	.compare2 = semanage_ibpkey_compare2,
	.compare2_qsort = semanage_ibpkey_compare2_qsort,
	.free = semanage_ibpkey_free,
};
