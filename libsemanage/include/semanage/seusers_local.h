/* Copyright (C) 2005 Red Hat, Inc. */

#ifndef _SEMANAGE_SEUSERS_LOCAL_H_
#define _SEMANAGE_SEUSERS_LOCAL_H_

#include <semanage/seuser_record.h>
#include <semanage/handle.h>

extern int semanage_seuser_modify_local(semanage_handle_t * handle,
					const semanage_seuser_key_t * key,
					const semanage_seuser_t * data);

extern int semanage_seuser_del_local(semanage_handle_t * handle,
				     const semanage_seuser_key_t * key);

extern int semanage_seuser_query_local(semanage_handle_t * handle,
				       const semanage_seuser_key_t * key,
				       semanage_seuser_t ** response);

extern int semanage_seuser_exists_local(semanage_handle_t * handle,
					const semanage_seuser_key_t * key,
					int *response);

extern int semanage_seuser_count_local(semanage_handle_t * handle,
				       unsigned int *response);

extern int semanage_seuser_iterate_local(semanage_handle_t * handle,
					 int (*handler) (const semanage_seuser_t
							 * record, void *varg),
					 void *handler_arg);

extern int semanage_seuser_list_local(semanage_handle_t * handle,
				      semanage_seuser_t *** records,
				      unsigned int *count);

#endif
