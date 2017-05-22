/* Copyright (C) 2017 Mellanox Techonologies Inc */

#ifndef _SEMANAGE_IBENDPORTS_POLICY_H_
#define _SEMANAGE_IBENDPORTS_POLICY_H_

#include <semanage/handle.h>
#include <semanage/ibendport_record.h>

extern int semanage_ibendport_query(semanage_handle_t *handle,
				    const semanage_ibendport_key_t *key,
				    semanage_ibendport_t **response);

extern int semanage_ibendport_exists(semanage_handle_t *handle,
				     const semanage_ibendport_key_t *key, int *response);

extern int semanage_ibendport_count(semanage_handle_t *handle,
				    unsigned int *response);

extern int semanage_ibendport_iterate(semanage_handle_t *handle,
				      int (*handler)(const semanage_ibendport_t *record,
						     void *varg),
				      void *handler_arg);

extern int semanage_ibendport_list(semanage_handle_t *handle,
				   semanage_ibendport_t ***records,
				   unsigned int *count);

#endif
