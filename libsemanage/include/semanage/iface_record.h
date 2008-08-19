/* Copyright (C) 2005 Red Hat, Inc. */

#ifndef _SEMANAGE_IFACE_RECORD_H_
#define _SEMANAGE_IFACE_RECORD_H_

#include <semanage/context_record.h>
#include <semanage/handle.h>

#ifndef _SEMANAGE_IFACE_DEFINED_
struct semanage_iface;
struct semanage_iface_key;
typedef struct semanage_iface semanage_iface_t;
typedef struct semanage_iface_key semanage_iface_key_t;
#define _SEMANAGE_IFACE_DEFINED_
#endif

/* Key */
extern int semanage_iface_compare(const semanage_iface_t * iface,
				  const semanage_iface_key_t * key);

extern int semanage_iface_compare2(const semanage_iface_t * iface,
				   const semanage_iface_t * iface2);

extern int semanage_iface_key_create(semanage_handle_t * handle,
				     const char *name,
				     semanage_iface_key_t ** key_ptr);

extern int semanage_iface_key_extract(semanage_handle_t * handle,
				      const semanage_iface_t * iface,
				      semanage_iface_key_t ** key_ptr);

extern void semanage_iface_key_free(semanage_iface_key_t * key);

/* Name */
extern const char *semanage_iface_get_name(const semanage_iface_t * iface);

extern int semanage_iface_set_name(semanage_handle_t * handle,
				   semanage_iface_t * iface, const char *name);

/* Context */
extern semanage_context_t *semanage_iface_get_ifcon(const semanage_iface_t *
						    iface);

extern int semanage_iface_set_ifcon(semanage_handle_t * handle,
				    semanage_iface_t * iface,
				    semanage_context_t * con);

extern semanage_context_t *semanage_iface_get_msgcon(const semanage_iface_t *
						     iface);

extern int semanage_iface_set_msgcon(semanage_handle_t * handle,
				     semanage_iface_t * iface,
				     semanage_context_t * con);

/* Create/Clone/Destroy */
extern int semanage_iface_create(semanage_handle_t * handle,
				 semanage_iface_t ** iface_ptr);

extern int semanage_iface_clone(semanage_handle_t * handle,
				const semanage_iface_t * iface,
				semanage_iface_t ** iface_ptr);

extern void semanage_iface_free(semanage_iface_t * iface);

#endif
