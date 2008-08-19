/* Copyright (C) 2005 Red Hat, Inc. */

#ifndef _SEMANAGE_SEUSER_RECORD_H_
#define _SEMANAGE_SEUSER_RECORD_H_

#include <semanage/handle.h>

struct semanage_seuser;
struct semanage_seuser_key;
typedef struct semanage_seuser semanage_seuser_t;
typedef struct semanage_seuser_key semanage_seuser_key_t;

/* Key */
extern int semanage_seuser_key_create(semanage_handle_t * handle,
				      const char *name,
				      semanage_seuser_key_t ** key);

extern int semanage_seuser_key_extract(semanage_handle_t * handle,
				       const semanage_seuser_t * seuser,
				       semanage_seuser_key_t ** key);

extern void semanage_seuser_key_free(semanage_seuser_key_t * key);

extern int semanage_seuser_compare(const semanage_seuser_t * seuser,
				   const semanage_seuser_key_t * key);

extern int semanage_seuser_compare2(const semanage_seuser_t * seuser,
				    const semanage_seuser_t * seuser2);

/* Name */
extern const char *semanage_seuser_get_name(const semanage_seuser_t * seuser);

extern int semanage_seuser_set_name(semanage_handle_t * handle,
				    semanage_seuser_t * seuser,
				    const char *name);

/* Selinux Name */
extern const char *semanage_seuser_get_sename(const semanage_seuser_t * seuser);

extern int semanage_seuser_set_sename(semanage_handle_t * handle,
				      semanage_seuser_t * seuser,
				      const char *sename);

/* MLS */
extern const char *semanage_seuser_get_mlsrange(const semanage_seuser_t *
						seuser);

extern int semanage_seuser_set_mlsrange(semanage_handle_t * handle,
					semanage_seuser_t * seuser,
					const char *mls_range);

/* Create/Clone/Destroy */
extern int semanage_seuser_create(semanage_handle_t * handle,
				  semanage_seuser_t ** seuser_ptr);

extern int semanage_seuser_clone(semanage_handle_t * handle,
				 const semanage_seuser_t * seuser,
				 semanage_seuser_t ** seuser_ptr);

extern void semanage_seuser_free(semanage_seuser_t * seuser);
#endif
