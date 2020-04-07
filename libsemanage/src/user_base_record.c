/* Copyright (C) 2005 Red Hat, Inc. */

/* Object: semanage_user_base_t (SELinux User/Class Policy Object)
 * Object: semanage_user_key_t (SELinux User/Class Key)
 * Implements: record_t (Database Record)
 * Implements: record_key_t (Database Record Key)
 */

#include <sepol/user_record.h>

typedef sepol_user_key_t semanage_user_key_t;
#define _SEMANAGE_USER_KEY_DEFINED_

typedef sepol_user_t semanage_user_base_t;
#define _SEMANAGE_USER_BASE_DEFINED_

typedef semanage_user_base_t record_t;
typedef semanage_user_key_t record_key_t;
#define DBASE_RECORD_DEFINED

#include <stdlib.h>
#include "user_internal.h"
#include "handle.h"
#include "database.h"
#include "debug.h"

/* Key */
 int semanage_user_base_key_extract(semanage_handle_t * handle,
					  const semanage_user_base_t * user,
					  semanage_user_key_t ** key)
{

	return sepol_user_key_extract(handle->sepolh, user, key);
}

static int semanage_user_base_compare(const semanage_user_base_t * user,
				      const semanage_user_key_t * key)
{

	return sepol_user_compare(user, key);
}

static int semanage_user_base_compare2(const semanage_user_base_t * user,
				       const semanage_user_base_t * user2)
{

	return sepol_user_compare2(user, user2);
}

static int semanage_user_base_compare2_qsort(const semanage_user_base_t ** user,
					     const semanage_user_base_t **
					     user2)
{

	return sepol_user_compare2(*user, *user2);
}

/* Name */
 const char *semanage_user_base_get_name(const semanage_user_base_t *
					       user)
{

	return sepol_user_get_name(user);
}

 int semanage_user_base_set_name(semanage_handle_t * handle,
				       semanage_user_base_t * user,
				       const char *name)
{

	return sepol_user_set_name(handle->sepolh, user, name);
}

/* MLS */
 const char *semanage_user_base_get_mlslevel(const semanage_user_base_t *
						   user)
{

	return sepol_user_get_mlslevel(user);
}

 int semanage_user_base_set_mlslevel(semanage_handle_t * handle,
					   semanage_user_base_t * user,
					   const char *mls_level)
{

	return sepol_user_set_mlslevel(handle->sepolh, user, mls_level);
}

 const char *semanage_user_base_get_mlsrange(const semanage_user_base_t *
						   user)
{

	return sepol_user_get_mlsrange(user);
}

 int semanage_user_base_set_mlsrange(semanage_handle_t * handle,
					   semanage_user_base_t * user,
					   const char *mls_range)
{

	return sepol_user_set_mlsrange(handle->sepolh, user, mls_range);
}

/* Role management */
 int semanage_user_base_get_num_roles(const semanage_user_base_t * user)
{

	return sepol_user_get_num_roles(user);
}

 int semanage_user_base_add_role(semanage_handle_t * handle,
				       semanage_user_base_t * user,
				       const char *role)
{

	return sepol_user_add_role(handle->sepolh, user, role);
}

 void semanage_user_base_del_role(semanage_user_base_t * user,
					const char *role)
{

	sepol_user_del_role(user, role);
}

 int semanage_user_base_has_role(const semanage_user_base_t * user,
				       const char *role)
{

	return sepol_user_has_role(user, role);
}

 int semanage_user_base_get_roles(semanage_handle_t * handle,
					const semanage_user_base_t * user,
					const char ***roles_arr,
					unsigned int *num_roles)
{

	return sepol_user_get_roles(handle->sepolh, user, roles_arr, num_roles);
}

 int semanage_user_base_set_roles(semanage_handle_t * handle,
					semanage_user_base_t * user,
					const char **roles_arr,
					unsigned int num_roles)
{

	return sepol_user_set_roles(handle->sepolh, user, roles_arr, num_roles);
}

/* Create/Clone/Destroy */
 int semanage_user_base_create(semanage_handle_t * handle,
				     semanage_user_base_t ** user_ptr)
{

	return sepol_user_create(handle->sepolh, user_ptr);
}

 int semanage_user_base_clone(semanage_handle_t * handle,
				    const semanage_user_base_t * user,
				    semanage_user_base_t ** user_ptr)
{

	return sepol_user_clone(handle->sepolh, user, user_ptr);
}

 void semanage_user_base_free(semanage_user_base_t * user)
{

	sepol_user_free(user);
}

/* Record base functions */
record_table_t SEMANAGE_USER_BASE_RTABLE = {
	.create = semanage_user_base_create,
	.key_extract = semanage_user_base_key_extract,
	.key_free = semanage_user_key_free,
	.clone = semanage_user_base_clone,
	.compare = semanage_user_base_compare,
	.compare2 = semanage_user_base_compare2,
	.compare2_qsort = semanage_user_base_compare2_qsort,
	.free = semanage_user_base_free,
};
