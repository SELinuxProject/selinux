/* Copyright (C) 2005 Red Hat, Inc. */

#ifndef _SEMANAGE_INTERFACES_LOCAL_H_
#define _SEMANAGE_INTERFACES_LOCAL_H_

#include <semanage/iface_record.h>
#include <semanage/handle.h>

extern int semanage_iface_modify_local(semanage_handle_t * handle,
				       const semanage_iface_key_t * key,
				       const semanage_iface_t * data);

extern int semanage_iface_del_local(semanage_handle_t * handle,
				    const semanage_iface_key_t * key);

extern int semanage_iface_query_local(semanage_handle_t * handle,
				      const semanage_iface_key_t * key,
				      semanage_iface_t ** response);

extern int semanage_iface_exists_local(semanage_handle_t * handle,
				       const semanage_iface_key_t * key,
				       int *response);

extern int semanage_iface_count_local(semanage_handle_t * handle,
				      unsigned int *response);

extern int semanage_iface_iterate_local(semanage_handle_t * handle,
					int (*handler) (const semanage_iface_t *
							record, void *varg),
					void *handler_arg);

extern int semanage_iface_list_local(semanage_handle_t * handle,
				     semanage_iface_t *** records,
				     unsigned int *count);

#endif
