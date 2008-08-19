/* Copyright (C) 2005 Red Hat, Inc. */

#ifndef _SEMANAGE_NODES_POLICY_H_
#define _SEMANAGE_NODES_POLICY_H_

#include <semanage/handle.h>
#include <semanage/node_record.h>

extern int semanage_node_query(semanage_handle_t * handle,
			       const semanage_node_key_t * key,
			       semanage_node_t ** response);

extern int semanage_node_exists(semanage_handle_t * handle,
				const semanage_node_key_t * key, int *response);

extern int semanage_node_count(semanage_handle_t * handle,
			       unsigned int *response);

extern int semanage_node_iterate(semanage_handle_t * handle,
				 int (*handler) (const semanage_node_t * record,
						 void *varg),
				 void *handler_arg);

extern int semanage_node_list(semanage_handle_t * handle,
			      semanage_node_t *** records, unsigned int *count);

#endif
