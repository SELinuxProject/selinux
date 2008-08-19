/* Copyright (C) 2005 Red Hat, Inc. */

#ifndef _SEMANAGE_CONTEXT_RECORD_H_
#define _SEMANAGE_CONTEXT_RECORD_H_

#include <semanage/handle.h>

#ifndef _SEMANAGE_CONTEXT_DEFINED_
struct semanage_context;
typedef struct semanage_context semanage_context_t;
#define _SEMANAGE_CONTEXT_DEFINED_
#endif

/* User */
extern const char *semanage_context_get_user(const semanage_context_t * con);

extern int semanage_context_set_user(semanage_handle_t * handle,
				     semanage_context_t * con,
				     const char *user);

/* Role */
extern const char *semanage_context_get_role(const semanage_context_t * con);

extern int semanage_context_set_role(semanage_handle_t * handle,
				     semanage_context_t * con,
				     const char *role);

/* Type */
extern const char *semanage_context_get_type(const semanage_context_t * con);

extern int semanage_context_set_type(semanage_handle_t * handle,
				     semanage_context_t * con,
				     const char *type);

/* MLS */
extern const char *semanage_context_get_mls(const semanage_context_t * con);

extern int semanage_context_set_mls(semanage_handle_t * handle,
				    semanage_context_t * con,
				    const char *mls_range);

/* Create/Clone/Destroy */
extern int semanage_context_create(semanage_handle_t * handle,
				   semanage_context_t ** con_ptr);

extern int semanage_context_clone(semanage_handle_t * handle,
				  const semanage_context_t * con,
				  semanage_context_t ** con_ptr);

extern void semanage_context_free(semanage_context_t * con);

/* Parse to/from string */
extern int semanage_context_from_string(semanage_handle_t * handle,
					const char *str,
					semanage_context_t ** con);

extern int semanage_context_to_string(semanage_handle_t * handle,
				      const semanage_context_t * con,
				      char **str_ptr);

#endif
