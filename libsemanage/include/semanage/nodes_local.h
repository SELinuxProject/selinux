/* Copyright (C) 2005 Red Hat, Inc. */

#ifndef _SEMANAGE_NODES_LOCAL_H_
#define _SEMANAGE_NODES_LOCAL_H_

#include <semanage/node_record.h>
#include <semanage/handle.h>

extern int semanage_node_modify_local(semanage_handle_t * handle,
				      const semanage_node_key_t * key,
				      const semanage_node_t * data);

extern int semanage_node_del_local(semanage_handle_t * handle,
				   const semanage_node_key_t * key);

extern int semanage_node_query_local(semanage_handle_t * handle,
				     const semanage_node_key_t * key,
				     semanage_node_t ** response);

extern int semanage_node_exists_local(semanage_handle_t * handle,
				      const semanage_node_key_t * key,
				      int *response);

extern int semanage_node_count_local(semanage_handle_t * handle,
				     unsigned int *response);

extern int semanage_node_iterate_local(semanage_handle_t * handle,
				       int (*handler) (const semanage_node_t *
						       record, void *varg),
				       void *handler_arg);

extern int semanage_node_list_local(semanage_handle_t * handle,
				    semanage_node_t *** records,
				    unsigned int *count);

#endif
