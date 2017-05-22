/* Copyright (C) 2017 Mellanox Technologies Inc */

#ifndef _SEMANAGE_IBPKEY_RECORD_H_
#define _SEMANAGE_IBPKEY_RECORD_H_

#include <semanage/context_record.h>
#include <semanage/handle.h>
#include <stddef.h>
#include <stdint.h>

#ifndef _SEMANAGE_IBPKEY_DEFINED_
struct semanage_ibpkey;
struct semanage_ibpkey_key;
typedef struct semanage_ibpkey semanage_ibpkey_t;
typedef struct semanage_ibpkey_key semanage_ibpkey_key_t;
#define _SEMANAGE_IBPKEY_DEFINED_
#endif

extern int semanage_ibpkey_compare(const semanage_ibpkey_t *ibpkey,
				   const semanage_ibpkey_key_t *key);

extern int semanage_ibpkey_compare2(const semanage_ibpkey_t *ibpkey,
				    const semanage_ibpkey_t *ibpkey2);

extern int semanage_ibpkey_key_create(semanage_handle_t *handle,
				      const char *subnet_prefix,
				      int low, int high,
				      semanage_ibpkey_key_t **key_ptr);

extern int semanage_ibpkey_key_extract(semanage_handle_t *handle,
				       const semanage_ibpkey_t *ibpkey,
				       semanage_ibpkey_key_t **key_ptr);

extern void semanage_ibpkey_key_free(semanage_ibpkey_key_t *key);

extern int semanage_ibpkey_get_subnet_prefix(semanage_handle_t *handle,
					     const semanage_ibpkey_t *ibpkey,
					     char **subnet_prefix_ptr);

extern uint64_t semanage_ibpkey_get_subnet_prefix_bytes(const semanage_ibpkey_t *ibpkey);

extern int semanage_ibpkey_set_subnet_prefix(semanage_handle_t *handle,
					     semanage_ibpkey_t *ibpkey,
					     const char *subnet_prefix);

extern void semanage_ibpkey_set_subnet_prefix_bytes(semanage_ibpkey_t *ibpkey,
						    uint64_t subnet_prefix);

extern int semanage_ibpkey_get_low(const semanage_ibpkey_t *ibpkey);

extern int semanage_ibpkey_get_high(const semanage_ibpkey_t *ibpkey);

extern void semanage_ibpkey_set_pkey(semanage_ibpkey_t *ibpkey, int pkey_num);

extern void semanage_ibpkey_set_range(semanage_ibpkey_t *ibpkey, int low, int high);

extern semanage_context_t *semanage_ibpkey_get_con(const semanage_ibpkey_t *ibpkey);

extern int semanage_ibpkey_set_con(semanage_handle_t *handle,
				   semanage_ibpkey_t *ibpkey,
				   semanage_context_t *con);

extern int semanage_ibpkey_create(semanage_handle_t *handle,
				  semanage_ibpkey_t **ibpkey_ptr);

extern int semanage_ibpkey_clone(semanage_handle_t *handle,
				 const semanage_ibpkey_t *ibpkey,
				 semanage_ibpkey_t **ibpkey_ptr);

extern void semanage_ibpkey_free(semanage_ibpkey_t *ibpkey);

#endif
