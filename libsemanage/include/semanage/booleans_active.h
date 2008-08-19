/* Copyright (C) 2005 Red Hat, Inc. */

#ifndef _SEMANAGE_BOOLEANS_ACTIVE_H_
#define _SEMANAGE_BOOLEANS_ACTIVE_H_

#include <semanage/boolean_record.h>
#include <semanage/handle.h>

extern int semanage_bool_set_active(semanage_handle_t * handle,
				    const semanage_bool_key_t * key,
				    const semanage_bool_t * data);

extern int semanage_bool_query_active(semanage_handle_t * handle,
				      const semanage_bool_key_t * key,
				      semanage_bool_t ** response);

extern int semanage_bool_exists_active(semanage_handle_t * handle,
				       const semanage_bool_key_t * key,
				       int *response);

extern int semanage_bool_count_active(semanage_handle_t * handle,
				      unsigned int *response);

extern int semanage_bool_iterate_active(semanage_handle_t * handle,
					int (*handler) (const semanage_bool_t *
							record, void *varg),
					void *handler_arg);

extern int semanage_bool_list_active(semanage_handle_t * handle,
				     semanage_bool_t *** records,
				     unsigned int *count);

#endif
