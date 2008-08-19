/* Copyright (C) 2005 Red Hat, Inc. */

#ifndef _SEMANAGE_SEUSERS_POLICY_H_
#define _SEMANAGE_SEUSERS_POLICY_H_

#include <semanage/seuser_record.h>
#include <semanage/handle.h>

extern int semanage_seuser_query(semanage_handle_t * handle,
				 const semanage_seuser_key_t * key,
				 semanage_seuser_t ** response);

extern int semanage_seuser_exists(semanage_handle_t * handle,
				  const semanage_seuser_key_t * key,
				  int *response);

extern int semanage_seuser_count(semanage_handle_t * handle,
				 unsigned int *response);

extern int semanage_seuser_iterate(semanage_handle_t * handle,
				   int (*handler) (const semanage_seuser_t *
						   record, void *varg),
				   void *handler_arg);

extern int semanage_seuser_list(semanage_handle_t * handle,
				semanage_seuser_t *** records,
				unsigned int *count);

#endif
