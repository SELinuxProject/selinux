/* Copyright (C) 2017 Mellanox Technolgies Inc. */

#ifndef _SEMANAGE_IBPKEYS_POLICY_H_
#define _SEMANAGE_IBPKEYS_POLICY_H_

#include <semanage/handle.h>
#include <semanage/ibpkey_record.h>

extern int semanage_ibpkey_query(semanage_handle_t *handle,
				 const semanage_ibpkey_key_t *key,
				 semanage_ibpkey_t **response);

extern int semanage_ibpkey_exists(semanage_handle_t *handle,
				  const semanage_ibpkey_key_t *key, int *response);

extern int semanage_ibpkey_count(semanage_handle_t *handle,
				 unsigned int *response);

extern int semanage_ibpkey_iterate(semanage_handle_t *handle,
				   int (*handler)(const semanage_ibpkey_t *record,
						  void *varg),
				   void *handler_arg);

extern int semanage_ibpkey_list(semanage_handle_t *handle,
				semanage_ibpkey_t ***records,
				unsigned int *count);

#endif
