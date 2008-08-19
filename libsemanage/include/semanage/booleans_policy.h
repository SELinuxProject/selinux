/* Copyright (C) 2005 Red Hat, Inc. */

#ifndef _SEMANAGE_BOOLEANS_POLICY_H_
#define _SEMANAGE_BOOLEANS_POLICY_H_

#include <semanage/handle.h>
#include <semanage/boolean_record.h>

extern int semanage_bool_query(semanage_handle_t * handle,
			       const semanage_bool_key_t * key,
			       semanage_bool_t ** response);

extern int semanage_bool_exists(semanage_handle_t * handle,
				const semanage_bool_key_t * key, int *response);

extern int semanage_bool_count(semanage_handle_t * handle,
			       unsigned int *response);

extern int semanage_bool_iterate(semanage_handle_t * handle,
				 int (*handler) (const semanage_bool_t * record,
						 void *varg),
				 void *handler_arg);

extern int semanage_bool_list(semanage_handle_t * handle,
			      semanage_bool_t *** records, unsigned int *count);

#endif
