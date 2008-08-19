/* Copyright (C) 2005 Red Hat, Inc. */

#ifndef _SEMANAGE_PORTS_POLICY_H_
#define _SEMANAGE_PORTS_POLICY_H_

#include <semanage/handle.h>
#include <semanage/port_record.h>

extern int semanage_port_query(semanage_handle_t * handle,
			       const semanage_port_key_t * key,
			       semanage_port_t ** response);

extern int semanage_port_exists(semanage_handle_t * handle,
				const semanage_port_key_t * key, int *response);

extern int semanage_port_count(semanage_handle_t * handle,
			       unsigned int *response);

extern int semanage_port_iterate(semanage_handle_t * handle,
				 int (*handler) (const semanage_port_t * record,
						 void *varg),
				 void *handler_arg);

extern int semanage_port_list(semanage_handle_t * handle,
			      semanage_port_t *** records, unsigned int *count);

#endif
