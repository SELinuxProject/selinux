/* Copyright (C) 2017 Mellanox Technologies Inc */

#ifndef _SEMANAGE_IBENDPORTS_LOCAL_H_
#define _SEMANAGE_IBENDPORTS_LOCAL_H_

#include <semanage/ibendport_record.h>
#include <semanage/handle.h>

extern int semanage_ibendport_modify_local(semanage_handle_t *handle,
					   const semanage_ibendport_key_t *key,
					   const semanage_ibendport_t *data);

extern int semanage_ibendport_del_local(semanage_handle_t *handle,
					const semanage_ibendport_key_t *key);

extern int semanage_ibendport_query_local(semanage_handle_t *handle,
					  const semanage_ibendport_key_t *key,
					  semanage_ibendport_t **response);

extern int semanage_ibendport_exists_local(semanage_handle_t *handle,
					   const semanage_ibendport_key_t *key,
					   int *response);

extern int semanage_ibendport_count_local(semanage_handle_t *handle,
					  unsigned int *response);

extern int semanage_ibendport_iterate_local(semanage_handle_t *handle,
					    int (*handler)(const semanage_ibendport_t *record,
							   void *varg),
					    void *handler_arg);

extern int semanage_ibendport_list_local(semanage_handle_t *handle,
					 semanage_ibendport_t ***records,
					 unsigned int *count);

#endif
