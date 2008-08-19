/* Copyright (C) 2005 Red Hat, Inc. */

#ifndef _SEMANAGE_NODE_RECORD_H_
#define _SEMANAGE_NODE_RECORD_H_

#include <semanage/context_record.h>
#include <semanage/handle.h>
#include <stddef.h>

#ifndef _SEMANAGE_NODE_DEFINED_
struct semanage_node;
struct semanage_node_key;
typedef struct semanage_node semanage_node_t;
typedef struct semanage_node_key semanage_node_key_t;
#define _SEMANAGE_NODE_DEFINED_
#endif

#define SEMANAGE_PROTO_IP4 0
#define SEMANAGE_PROTO_IP6 1

/* Key */
extern int semanage_node_compare(const semanage_node_t * node,
				 const semanage_node_key_t * key);

extern int semanage_node_compare2(const semanage_node_t * node,
				  const semanage_node_t * node2);

extern int semanage_node_key_create(semanage_handle_t * handle,
				    const char *addr,
				    const char *mask,
				    int proto, semanage_node_key_t ** key_ptr);

extern int semanage_node_key_extract(semanage_handle_t * handle,
				     const semanage_node_t * node,
				     semanage_node_key_t ** key_ptr);

extern void semanage_node_key_free(semanage_node_key_t * key);

/* Address */
extern int semanage_node_get_addr(semanage_handle_t * handle,
				  const semanage_node_t * node, char **addr);

extern int semanage_node_get_addr_bytes(semanage_handle_t * handle,
					const semanage_node_t * node,
					char **addr, size_t * addr_sz);

extern int semanage_node_set_addr(semanage_handle_t * handle,
				  semanage_node_t * node,
				  int proto, const char *addr);

extern int semanage_node_set_addr_bytes(semanage_handle_t * handle,
					semanage_node_t * node,
					const char *addr, size_t addr_sz);

/* Netmask */
extern int semanage_node_get_mask(semanage_handle_t * handle,
				  const semanage_node_t * node, char **mask);

extern int semanage_node_get_mask_bytes(semanage_handle_t * handle,
					const semanage_node_t * node,
					char **mask, size_t * mask_sz);

extern int semanage_node_set_mask(semanage_handle_t * handle,
				  semanage_node_t * node,
				  int proto, const char *mask);

extern int semanage_node_set_mask_bytes(semanage_handle_t * handle,
					semanage_node_t * node,
					const char *mask, size_t mask_sz);

/* Protocol */
extern int semanage_node_get_proto(const semanage_node_t * node);

extern void semanage_node_set_proto(semanage_node_t * node, int proto);

extern const char *semanage_node_get_proto_str(int proto);

/* Context */
extern semanage_context_t *semanage_node_get_con(const semanage_node_t * node);

extern int semanage_node_set_con(semanage_handle_t * handle,
				 semanage_node_t * node,
				 semanage_context_t * con);

/* Create/Clone/Destroy */
extern int semanage_node_create(semanage_handle_t * handle,
				semanage_node_t ** node_ptr);

extern int semanage_node_clone(semanage_handle_t * handle,
			       const semanage_node_t * node,
			       semanage_node_t ** node_ptr);

extern void semanage_node_free(semanage_node_t * node);

#endif
