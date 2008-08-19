/* Copyright (C) 2005 Red Hat, Inc. */

#ifndef _SEMANAGE_BOOLEAN_RECORD_H_
#define _SEMANAGE_BOOLEAN_RECORD_H_

#include <semanage/handle.h>

#ifndef _SEMANAGE_BOOL_DEFINED_
struct semanage_bool;
struct semanage_bool_key;
typedef struct semanage_bool semanage_bool_t;
typedef struct semanage_bool_key semanage_bool_key_t;
#define _SEMANAGE_BOOL_DEFINED_
#endif

/* Key */
extern int semanage_bool_key_create(semanage_handle_t * handle,
				    const char *name,
				    semanage_bool_key_t ** key);

extern int semanage_bool_key_extract(semanage_handle_t * handle,
				     const semanage_bool_t * boolean,
				     semanage_bool_key_t ** key);

extern void semanage_bool_key_free(semanage_bool_key_t * key);

extern int semanage_bool_compare(const semanage_bool_t * boolean,
				 const semanage_bool_key_t * key);

extern int semanage_bool_compare2(const semanage_bool_t * boolean,
				  const semanage_bool_t * boolean2);

/* Name */
extern const char *semanage_bool_get_name(const semanage_bool_t * boolean);

extern int semanage_bool_set_name(semanage_handle_t * handle,
				  semanage_bool_t * boolean, const char *name);

/* Value */
extern int semanage_bool_get_value(const semanage_bool_t * boolean);

extern void semanage_bool_set_value(semanage_bool_t * boolean, int value);

/* Create/Clone/Destroy */
extern int semanage_bool_create(semanage_handle_t * handle,
				semanage_bool_t ** bool_ptr);

extern int semanage_bool_clone(semanage_handle_t * handle,
			       const semanage_bool_t * boolean,
			       semanage_bool_t ** bool_ptr);

extern void semanage_bool_free(semanage_bool_t * boolean);

#endif
