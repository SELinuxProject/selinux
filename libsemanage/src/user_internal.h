#ifndef _SEMANAGE_USER_INTERNAL_H_
#define _SEMANAGE_USER_INTERNAL_H_

#include <sepol/user_record.h>
#include <semanage/user_record.h>
#include <semanage/users_local.h>
#include <semanage/users_policy.h>
#include "database.h"
#include "handle.h"

/* USER record: method table */
extern record_table_t SEMANAGE_USER_RTABLE;

/* USER BASE record: method table */
extern record_table_t SEMANAGE_USER_BASE_RTABLE;

/* USER EXTRA record: method table */
extern record_table_t SEMANAGE_USER_EXTRA_RTABLE;

/* ============ Init/Release functions ========== */

/* USER BASE record, FILE backend */
extern int user_base_file_dbase_init(semanage_handle_t * handle,
				     const char *path_ro,
				     const char *path_rw,
				     dbase_config_t * dconfig);

extern void user_base_file_dbase_release(dbase_config_t * dconfig);

/* USER EXTRA record, FILE backend */
extern int user_extra_file_dbase_init(semanage_handle_t * handle,
				      const char *path_ro,
				      const char *path_rw,
				      dbase_config_t * dconfig);

extern void user_extra_file_dbase_release(dbase_config_t * dconfig);

/* USER BASE record, POLICYDB backend */
extern int user_base_policydb_dbase_init(semanage_handle_t * handle,
					 dbase_config_t * dconfig);

extern void user_base_policydb_dbase_release(dbase_config_t * dconfig);

/* USER record, JOIN backend */
extern int user_join_dbase_init(semanage_handle_t * handle,
				dbase_config_t * join1,
				dbase_config_t * join2,
				dbase_config_t * dconfig);

extern void user_join_dbase_release(dbase_config_t * dconfig);

/*======= Internal API: Base (Policy) User record ====== */

#ifndef _SEMANAGE_USER_BASE_DEFINED_
struct semanage_user_base;
typedef struct semanage_user_base semanage_user_base_t;
#define _SEMANAGE_USER_BASE_DEFINED_
#endif

 int semanage_user_base_create(semanage_handle_t * handle,
				     semanage_user_base_t ** user_ptr);

 int semanage_user_base_clone(semanage_handle_t * handle,
				    const semanage_user_base_t * user,
				    semanage_user_base_t ** user_ptr);

 int semanage_user_base_key_extract(semanage_handle_t * handle,
					  const semanage_user_base_t * user,
					  semanage_user_key_t ** key);

 const char *semanage_user_base_get_name(const semanage_user_base_t *
					       user);

 int semanage_user_base_set_name(semanage_handle_t * handle,
				       semanage_user_base_t * user,
				       const char *name);

 const char *semanage_user_base_get_mlslevel(const semanage_user_base_t *
						   user);

 int semanage_user_base_set_mlslevel(semanage_handle_t * handle,
					   semanage_user_base_t * user,
					   const char *mls_level);

 const char *semanage_user_base_get_mlsrange(const semanage_user_base_t *
						   user);

 int semanage_user_base_set_mlsrange(semanage_handle_t * handle,
					   semanage_user_base_t * user,
					   const char *mls_range);

 int semanage_user_base_get_num_roles(const semanage_user_base_t * user);

 int semanage_user_base_add_role(semanage_handle_t * handle,
				       semanage_user_base_t * user,
				       const char *role);

 void semanage_user_base_del_role(semanage_user_base_t * user,
					const char *role);

 int semanage_user_base_has_role(const semanage_user_base_t * user,
				       const char *role);

 int semanage_user_base_get_roles(semanage_handle_t * handle,
					const semanage_user_base_t * user,
					const char ***roles_arr,
					unsigned int *num_roles);

 int semanage_user_base_set_roles(semanage_handle_t * handle,
					semanage_user_base_t * user,
					const char **roles_arr,
					unsigned int num_roles);

 void semanage_user_base_free(semanage_user_base_t * user);

/*=========== Internal API: Extra User record ==========*/
struct semanage_user_extra;
typedef struct semanage_user_extra semanage_user_extra_t;

 int semanage_user_extra_create(semanage_handle_t * handle,
				      semanage_user_extra_t ** user_extra_ptr);

 int semanage_user_extra_clone(semanage_handle_t * handle,
				     const semanage_user_extra_t * user_extra,
				     semanage_user_extra_t ** user_extra_ptr);

 const char *semanage_user_extra_get_name(const semanage_user_extra_t *
						user_extra);

 int semanage_user_extra_set_name(semanage_handle_t * handle,
					semanage_user_extra_t * user_extra,
					const char *name);

 const char *semanage_user_extra_get_prefix(const semanage_user_extra_t *
						  user_extra);

 int semanage_user_extra_set_prefix(semanage_handle_t * handle,
					  semanage_user_extra_t * user_extra,
					  const char *prefix);

 void semanage_user_extra_free(semanage_user_extra_t * user_extra);

/*======== Internal API: Join record ========== */
 void semanage_user_key_unpack(const semanage_user_key_t * key,
				     const char **name);

 int semanage_user_join(semanage_handle_t * handle,
			      const semanage_user_base_t * record1,
			      const semanage_user_extra_t * record2,
			      semanage_user_t ** result);

 int semanage_user_split(semanage_handle_t * handle,
			       const semanage_user_t * record,
			       semanage_user_base_t ** split1,
			       semanage_user_extra_t ** split2);

#endif
