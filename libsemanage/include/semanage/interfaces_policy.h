/* Copyright (C) 2005 Red Hat, Inc. */

#ifndef _SEMANAGE_INTERFACES_POLICY_H_
#define _SEMANAGE_INTERFACES_POLICY_H_

#include <semanage/handle.h>
#include <semanage/iface_record.h>

extern int semanage_iface_query(semanage_handle_t * handle,
				const semanage_iface_key_t * key,
				semanage_iface_t ** response);

extern int semanage_iface_exists(semanage_handle_t * handle,
				 const semanage_iface_key_t * key,
				 int *response);

extern int semanage_iface_count(semanage_handle_t * handle,
				unsigned int *response);

extern int semanage_iface_iterate(semanage_handle_t * handle,
				  int (*handler) (const semanage_iface_t *
						  record, void *varg),
				  void *handler_arg);

extern int semanage_iface_list(semanage_handle_t * handle,
			       semanage_iface_t *** records,
			       unsigned int *count);

#endif
