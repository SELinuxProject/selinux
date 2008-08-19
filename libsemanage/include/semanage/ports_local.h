/* Copyright (C) 2005 Red Hat, Inc. */

#ifndef _SEMANAGE_PORTS_LOCAL_H_
#define _SEMANAGE_PORTS_LOCAL_H_

#include <semanage/port_record.h>
#include <semanage/handle.h>

extern int semanage_port_modify_local(semanage_handle_t * handle,
				      const semanage_port_key_t * key,
				      const semanage_port_t * data);

extern int semanage_port_del_local(semanage_handle_t * handle,
				   const semanage_port_key_t * key);

extern int semanage_port_query_local(semanage_handle_t * handle,
				     const semanage_port_key_t * key,
				     semanage_port_t ** response);

extern int semanage_port_exists_local(semanage_handle_t * handle,
				      const semanage_port_key_t * key,
				      int *response);

extern int semanage_port_count_local(semanage_handle_t * handle,
				     unsigned int *response);

extern int semanage_port_iterate_local(semanage_handle_t * handle,
				       int (*handler) (const semanage_port_t *
						       record, void *varg),
				       void *handler_arg);

extern int semanage_port_list_local(semanage_handle_t * handle,
				    semanage_port_t *** records,
				    unsigned int *count);

#endif
