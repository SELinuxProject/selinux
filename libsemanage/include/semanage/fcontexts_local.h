/* Copyright (C) 2005 Red Hat, Inc. */

#ifndef _SEMANAGE_FCONTEXTS_LOCAL_H_
#define _SEMANAGE_FCONTEXTS_LOCAL_H_

#include <semanage/fcontext_record.h>
#include <semanage/handle.h>

extern int semanage_fcontext_modify_local(semanage_handle_t * handle,
					  const semanage_fcontext_key_t * key,
					  const semanage_fcontext_t * data);

extern int semanage_fcontext_del_local(semanage_handle_t * handle,
				       const semanage_fcontext_key_t * key);

extern int semanage_fcontext_query_local(semanage_handle_t * handle,
					 const semanage_fcontext_key_t * key,
					 semanage_fcontext_t ** response);

extern int semanage_fcontext_exists_local(semanage_handle_t * handle,
					  const semanage_fcontext_key_t * key,
					  int *response);

extern int semanage_fcontext_count_local(semanage_handle_t * handle,
					 unsigned int *response);

extern int semanage_fcontext_iterate_local(semanage_handle_t * handle,
					   int (*handler) (const
							   semanage_fcontext_t *
							   record, void *varg),
					   void *handler_arg);

extern int semanage_fcontext_list_local(semanage_handle_t * handle,
					semanage_fcontext_t *** records,
					unsigned int *count);

#endif
