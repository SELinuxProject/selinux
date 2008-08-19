/* Copyright (C) 2005 Red Hat, Inc. */

#ifndef _SEMANAGE_USERS_LOCAL_H_
#define _SEMANAGE_USERS_LOCAL_H_

#include <semanage/user_record.h>
#include <semanage/handle.h>

extern int semanage_user_modify_local(semanage_handle_t * handle,
				      const semanage_user_key_t * key,
				      const semanage_user_t * data);

extern int semanage_user_del_local(semanage_handle_t * handle,
				   const semanage_user_key_t * key);

extern int semanage_user_query_local(semanage_handle_t * handle,
				     const semanage_user_key_t * key,
				     semanage_user_t ** response);

extern int semanage_user_exists_local(semanage_handle_t * handle,
				      const semanage_user_key_t * key,
				      int *response);

extern int semanage_user_count_local(semanage_handle_t * handle,
				     unsigned int *response);

extern int semanage_user_iterate_local(semanage_handle_t * handle,
				       int (*handler) (const semanage_user_t *
						       record, void *varg),
				       void *handler_arg);

extern int semanage_user_list_local(semanage_handle_t * handle,
				    semanage_user_t *** records,
				    unsigned int *count);

#endif
