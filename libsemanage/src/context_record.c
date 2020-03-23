/* Copyright (C) 2005 Red Hat, Inc. */

#include <sepol/context_record.h>
#include "handle.h"

typedef sepol_context_t semanage_context_t;

#define _SEMANAGE_CONTEXT_DEFINED_

/* User */
const char *semanage_context_get_user(const semanage_context_t * con)
{

	return sepol_context_get_user(con);
}

int semanage_context_set_user(semanage_handle_t * handle,
			      semanage_context_t * con, const char *user)
{

	return sepol_context_set_user(handle->sepolh, con, user);
}

/* Role */
const char *semanage_context_get_role(const semanage_context_t * con)
{

	return sepol_context_get_role(con);
}

int semanage_context_set_role(semanage_handle_t * handle,
			      semanage_context_t * con, const char *role)
{

	return sepol_context_set_role(handle->sepolh, con, role);
}

/* Type */
const char *semanage_context_get_type(const semanage_context_t * con)
{

	return sepol_context_get_type(con);
}

int semanage_context_set_type(semanage_handle_t * handle,
			      semanage_context_t * con, const char *type)
{

	return sepol_context_set_type(handle->sepolh, con, type);
}

/* MLS */
const char *semanage_context_get_mls(const semanage_context_t * con)
{

	return sepol_context_get_mls(con);
}

int semanage_context_set_mls(semanage_handle_t * handle,
			     semanage_context_t * con, const char *mls_range)
{

	return sepol_context_set_mls(handle->sepolh, con, mls_range);
}

/* Create/Clone/Destroy */
int semanage_context_create(semanage_handle_t * handle,
			    semanage_context_t ** con_ptr)
{

	return sepol_context_create(handle->sepolh, con_ptr);
}

int semanage_context_clone(semanage_handle_t * handle,
			   const semanage_context_t * con,
			   semanage_context_t ** con_ptr)
{

	return sepol_context_clone(handle->sepolh, con, con_ptr);
}


void semanage_context_free(semanage_context_t * con)
{

	sepol_context_free(con);
}


/* Parse to/from string */
int semanage_context_from_string(semanage_handle_t * handle,
				 const char *str, semanage_context_t ** con)
{

	return sepol_context_from_string(handle->sepolh, str, con);
}


int semanage_context_to_string(semanage_handle_t * handle,
			       const semanage_context_t * con, char **str_ptr)
{

	return sepol_context_to_string(handle->sepolh, con, str_ptr);
}

