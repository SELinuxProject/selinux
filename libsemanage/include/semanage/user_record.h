/* Copyright (C) 2005 Red Hat, Inc. */

#ifndef _SEMANAGE_USER_RECORD_H_
#define _SEMANAGE_USER_RECORD_H_

#include <stddef.h>
#include <semanage/handle.h>

struct semanage_user;
typedef struct semanage_user semanage_user_t;

#ifndef _SEMANAGE_USER_KEY_DEFINED_
struct semanage_user_key;
typedef struct semanage_user_key semanage_user_key_t;
#define _SEMANAGE_USER_KEY_DEFINED_
#endif

/* Key */
extern int semanage_user_key_create(semanage_handle_t * handle,
				    const char *name,
				    semanage_user_key_t ** key);

extern int semanage_user_key_extract(semanage_handle_t * handle,
				     const semanage_user_t * user,
				     semanage_user_key_t ** key);

extern void semanage_user_key_free(semanage_user_key_t * key);

extern int semanage_user_compare(const semanage_user_t * user,
				 const semanage_user_key_t * key);

extern int semanage_user_compare2(const semanage_user_t * user,
				  const semanage_user_t * user2);

/* Name */
extern const char *semanage_user_get_name(const semanage_user_t * user);

extern int semanage_user_set_name(semanage_handle_t * handle,
				  semanage_user_t * user, const char *name);

/* Labeling prefix */
extern const char *semanage_user_get_prefix(const semanage_user_t * user);

extern int semanage_user_set_prefix(semanage_handle_t * handle,
				    semanage_user_t * user, const char *name);

/* MLS */
extern const char *semanage_user_get_mlslevel(const semanage_user_t * user);

extern int semanage_user_set_mlslevel(semanage_handle_t * handle,
				      semanage_user_t * user,
				      const char *mls_level);

extern const char *semanage_user_get_mlsrange(const semanage_user_t * user);

extern int semanage_user_set_mlsrange(semanage_handle_t * handle,
				      semanage_user_t * user,
				      const char *mls_range);

/* Role management */
extern int semanage_user_get_num_roles(const semanage_user_t * user);

extern int semanage_user_add_role(semanage_handle_t * handle,
				  semanage_user_t * user, const char *role);

extern void semanage_user_del_role(semanage_user_t * user, const char *role);

extern int semanage_user_has_role(const semanage_user_t * user,
				  const char *role);

extern int semanage_user_get_roles(semanage_handle_t * handle,
				   const semanage_user_t * user,
				   const char ***roles_arr,
				   unsigned int *num_roles);

extern int semanage_user_set_roles(semanage_handle_t * handle,
				   semanage_user_t * user,
				   const char **roles_arr,
				   unsigned int num_roles);

/* Create/Clone/Destroy */
extern int semanage_user_create(semanage_handle_t * handle,
				semanage_user_t ** user_ptr);

extern int semanage_user_clone(semanage_handle_t * handle,
			       const semanage_user_t * user,
			       semanage_user_t ** user_ptr);

extern void semanage_user_free(semanage_user_t * user);
#endif
