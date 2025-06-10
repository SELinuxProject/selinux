/* Copyright (C) 2005 Red Hat, Inc. */

/* Object: semanage_node_t (Network Port)
 * Object: semanage_node_key_t (Network Port Key)
 * Implements: record_t (Database Record)
 * Implements: record_key_t (Database Record Key)
 */

#include <sepol/context_record.h>
#include <sepol/node_record.h>
#include <stddef.h>

typedef sepol_context_t semanage_context_t;
typedef sepol_node_t semanage_node_t;
typedef sepol_node_key_t semanage_node_key_t;
#define _SEMANAGE_NODE_DEFINED_
#define _SEMANAGE_CONTEXT_DEFINED_

typedef semanage_node_t record_t;
typedef semanage_node_key_t record_key_t;
#define DBASE_RECORD_DEFINED

#include "node_internal.h"
#include "handle.h"
#include "database.h"

/* Key */
int semanage_node_compare(const semanage_node_t * node,
			  const semanage_node_key_t * key)
{

	return sepol_node_compare(node, key);
}


int semanage_node_compare2(const semanage_node_t * node,
			   const semanage_node_t * node2)
{

	return sepol_node_compare2(node, node2);
}


 int semanage_node_compare2_qsort(const void *p1, const void *p2)
{
	const semanage_node_t *const *node1 = p1;
	const semanage_node_t *const *node2 = p2;

	return sepol_node_compare2(*node1, *node2);
}

int semanage_node_key_create(semanage_handle_t * handle,
			     const char *addr,
			     const char *mask,
			     int proto, semanage_node_key_t ** key_ptr)
{

	return sepol_node_key_create(handle->sepolh, addr, mask, proto,
				     key_ptr);
}

int semanage_node_key_extract(semanage_handle_t * handle,
			      const semanage_node_t * node,
			      semanage_node_key_t ** key_ptr)
{

	return sepol_node_key_extract(handle->sepolh, node, key_ptr);
}


void semanage_node_key_free(semanage_node_key_t * key)
{

	sepol_node_key_free(key);
}


/* Address */
int semanage_node_get_addr(semanage_handle_t * handle,
			   const semanage_node_t * node, char **addr_ptr)
{

	return sepol_node_get_addr(handle->sepolh, node, addr_ptr);
}


int semanage_node_get_addr_bytes(semanage_handle_t * handle,
				 const semanage_node_t * node,
				 char **addr, size_t * addr_sz)
{

	return sepol_node_get_addr_bytes(handle->sepolh, node, addr, addr_sz);
}


int semanage_node_set_addr(semanage_handle_t * handle,
			   semanage_node_t * node, int proto, const char *addr)
{

	return sepol_node_set_addr(handle->sepolh, node, proto, addr);
}


int semanage_node_set_addr_bytes(semanage_handle_t * handle,
				 semanage_node_t * node,
				 const char *addr, size_t addr_sz)
{

	return sepol_node_set_addr_bytes(handle->sepolh, node, addr, addr_sz);
}


/* Netmask */
int semanage_node_get_mask(semanage_handle_t * handle,
			   const semanage_node_t * node, char **mask_ptr)
{

	return sepol_node_get_mask(handle->sepolh, node, mask_ptr);
}


int semanage_node_get_mask_bytes(semanage_handle_t * handle,
				 const semanage_node_t * node,
				 char **mask, size_t * mask_sz)
{

	return sepol_node_get_mask_bytes(handle->sepolh, node, mask, mask_sz);
}


int semanage_node_set_mask(semanage_handle_t * handle,
			   semanage_node_t * node, int proto, const char *mask)
{

	return sepol_node_set_mask(handle->sepolh, node, proto, mask);
}


int semanage_node_set_mask_bytes(semanage_handle_t * handle,
				 semanage_node_t * node,
				 const char *mask, size_t mask_sz)
{

	return sepol_node_set_mask_bytes(handle->sepolh, node, mask, mask_sz);
}


/* Protocol */
int semanage_node_get_proto(const semanage_node_t * node)
{

	return sepol_node_get_proto(node);
}


void semanage_node_set_proto(semanage_node_t * node, int proto)
{

	sepol_node_set_proto(node, proto);
}


const char *semanage_node_get_proto_str(int proto)
{

	return sepol_node_get_proto_str(proto);
}


/* Context */
semanage_context_t *semanage_node_get_con(const semanage_node_t * node)
{

	return sepol_node_get_con(node);
}


int semanage_node_set_con(semanage_handle_t * handle,
			  semanage_node_t * node, semanage_context_t * con)
{

	return sepol_node_set_con(handle->sepolh, node, con);
}


/* Create/Clone/Destroy */
int semanage_node_create(semanage_handle_t * handle,
			 semanage_node_t ** node_ptr)
{

	return sepol_node_create(handle->sepolh, node_ptr);
}


int semanage_node_clone(semanage_handle_t * handle,
			const semanage_node_t * node,
			semanage_node_t ** node_ptr)
{

	return sepol_node_clone(handle->sepolh, node, node_ptr);
}


void semanage_node_free(semanage_node_t * node)
{

	sepol_node_free(node);
}


/* Port base functions */
const record_table_t SEMANAGE_NODE_RTABLE = {
	.create = semanage_node_create,
	.key_extract = semanage_node_key_extract,
	.key_free = semanage_node_key_free,
	.clone = semanage_node_clone,
	.compare = semanage_node_compare,
	.compare2 = semanage_node_compare2,
	.compare2_qsort = semanage_node_compare2_qsort,
	.free = semanage_node_free,
};
