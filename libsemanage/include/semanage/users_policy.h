/* Copyright (C) 2005 Red Hat, Inc. */

#ifndef _SEMANAGE_USERS_POLICY_H_
#define _SEMANAGE_USERS_POLICY_H_

#include <semanage/handle.h>
#include <semanage/user_record.h>

extern int semanage_user_query(semanage_handle_t * handle,
			       const semanage_user_key_t * key,
			       semanage_user_t ** response);

extern int semanage_user_exists(semanage_handle_t * handle,
				const semanage_user_key_t * key, int *response);

extern int semanage_user_count(semanage_handle_t * handle,
			       unsigned int *response);

extern int semanage_user_iterate(semanage_handle_t * handle,
				 int (*handler) (const semanage_user_t * record,
						 void *varg),
				 void *handler_arg);

extern int semanage_user_list(semanage_handle_t * handle,
			      semanage_user_t *** records, unsigned int *count);

#endif
