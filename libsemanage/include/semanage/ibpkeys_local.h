/* Copyright (C) 2017 Mellanox Technologies Inc */

#ifndef _SEMANAGE_IBPKEYS_LOCAL_H_
#define _SEMANAGE_IBPKEYS_LOCAL_H_

#include <semanage/ibpkey_record.h>
#include <semanage/handle.h>

extern int semanage_ibpkey_modify_local(semanage_handle_t *handle,
					const semanage_ibpkey_key_t *key,
					const semanage_ibpkey_t *data);

extern int semanage_ibpkey_del_local(semanage_handle_t *handle,
				     const semanage_ibpkey_key_t *key);

extern int semanage_ibpkey_query_local(semanage_handle_t *handle,
				       const semanage_ibpkey_key_t *key,
				       semanage_ibpkey_t **response);

extern int semanage_ibpkey_exists_local(semanage_handle_t *handle,
					const semanage_ibpkey_key_t *key,
					int *response);

extern int semanage_ibpkey_count_local(semanage_handle_t *handle,
				       unsigned int *response);

extern int semanage_ibpkey_iterate_local(semanage_handle_t *handle,
					 int (*handler)(const semanage_ibpkey_t *
							record, void *varg),
					 void *handler_arg);

extern int semanage_ibpkey_list_local(semanage_handle_t *handle,
				      semanage_ibpkey_t ***records,
				      unsigned int *count);

#endif
