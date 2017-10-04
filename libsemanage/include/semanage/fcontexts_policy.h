/* Copyright (C) 2005 Red Hat, Inc. */

#ifndef _SEMANAGE_FCONTEXTS_POLICY_H_
#define _SEMANAGE_FCONTEXTS_POLICY_H_

#include <semanage/fcontext_record.h>
#include <semanage/handle.h>

extern int semanage_fcontext_query(semanage_handle_t * handle,
				   const semanage_fcontext_key_t * key,
				   semanage_fcontext_t ** response);

extern int semanage_fcontext_exists(semanage_handle_t * handle,
				    const semanage_fcontext_key_t * key,
				    int *response);

extern int semanage_fcontext_count(semanage_handle_t * handle,
				   unsigned int *response);

extern int semanage_fcontext_iterate(semanage_handle_t * handle,
				     int (*handler) (const semanage_fcontext_t *
						     record, void *varg),
				     void *handler_arg);

extern int semanage_fcontext_list(semanage_handle_t * handle,
				  semanage_fcontext_t *** records,
				  unsigned int *count);

extern int semanage_fcontext_list_homedirs(semanage_handle_t * handle,
				  semanage_fcontext_t *** records,
				  unsigned int *count);

#endif
