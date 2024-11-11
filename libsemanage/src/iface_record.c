/* Copyright (C) 2005 Red Hat, Inc. */

/* Object: semanage_iface_t (Network Interface)
 * Object: semanage_iface_key_t (Network Interface Key)
 * Implements: record_t (Database Record)
 * Implements: record_key_t (Database Record Key)
 */

#include <sepol/context_record.h>
#include <sepol/iface_record.h>

typedef sepol_context_t semanage_context_t;
typedef sepol_iface_t semanage_iface_t;
typedef sepol_iface_key_t semanage_iface_key_t;
#define _SEMANAGE_CONTEXT_DEFINED_
#define _SEMANAGE_IFACE_DEFINED_

typedef sepol_iface_t record_t;
typedef sepol_iface_key_t record_key_t;
#define DBASE_RECORD_DEFINED

#include "iface_internal.h"
#include "handle.h"
#include "database.h"

/* Key */
int semanage_iface_compare(const semanage_iface_t * iface,
			   const semanage_iface_key_t * key)
{

	return sepol_iface_compare(iface, key);
}


int semanage_iface_compare2(const semanage_iface_t * iface,
			    const semanage_iface_t * iface2)
{

	return sepol_iface_compare2(iface, iface2);
}


static int semanage_iface_compare2_qsort(const void *p1,
					 const void *p2)
{
	const semanage_iface_t *const *iface1 = p1;
	const semanage_iface_t *const *iface2 = p2;

	return sepol_iface_compare2(*iface1, *iface2);
}

int semanage_iface_key_create(semanage_handle_t * handle,
			      const char *name, semanage_iface_key_t ** key_ptr)
{

	return sepol_iface_key_create(handle->sepolh, name, key_ptr);
}

int semanage_iface_key_extract(semanage_handle_t * handle,
			       const semanage_iface_t * iface,
			       semanage_iface_key_t ** key_ptr)
{

	return sepol_iface_key_extract(handle->sepolh, iface, key_ptr);
}


void semanage_iface_key_free(semanage_iface_key_t * key)
{

	sepol_iface_key_free(key);
}


/* Name */
const char *semanage_iface_get_name(const semanage_iface_t * iface)
{

	return sepol_iface_get_name(iface);
}


int semanage_iface_set_name(semanage_handle_t * handle,
			    semanage_iface_t * iface, const char *name)
{

	return sepol_iface_set_name(handle->sepolh, iface, name);
}


/* Context */
semanage_context_t *semanage_iface_get_ifcon(const semanage_iface_t * iface)
{

	return sepol_iface_get_ifcon(iface);
}


int semanage_iface_set_ifcon(semanage_handle_t * handle,
			     semanage_iface_t * iface, semanage_context_t * con)
{

	return sepol_iface_set_ifcon(handle->sepolh, iface, con);
}


semanage_context_t *semanage_iface_get_msgcon(const semanage_iface_t * iface)
{

	return sepol_iface_get_msgcon(iface);
}


int semanage_iface_set_msgcon(semanage_handle_t * handle,
			      semanage_iface_t * iface,
			      semanage_context_t * con)
{

	return sepol_iface_set_msgcon(handle->sepolh, iface, con);
}


/* Create/Clone/Destroy */
int semanage_iface_create(semanage_handle_t * handle,
			  semanage_iface_t ** iface_ptr)
{

	return sepol_iface_create(handle->sepolh, iface_ptr);
}


int semanage_iface_clone(semanage_handle_t * handle,
			 const semanage_iface_t * iface,
			 semanage_iface_t ** iface_ptr)
{

	return sepol_iface_clone(handle->sepolh, iface, iface_ptr);
}


void semanage_iface_free(semanage_iface_t * iface)
{

	sepol_iface_free(iface);
}


/* Record base functions */
const record_table_t SEMANAGE_IFACE_RTABLE = {
	.create = semanage_iface_create,
	.key_extract = semanage_iface_key_extract,
	.key_free = semanage_iface_key_free,
	.clone = semanage_iface_clone,
	.compare = semanage_iface_compare,
	.compare2 = semanage_iface_compare2,
	.compare2_qsort = semanage_iface_compare2_qsort,
	.free = semanage_iface_free,
};
