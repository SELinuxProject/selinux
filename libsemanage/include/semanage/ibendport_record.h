/*Copyright (C) 2005 Red Hat, Inc. */

#ifndef _SEMANAGE_IBENDPORT_RECORD_H_
#define _SEMANAGE_IBENDPORT_RECORD_H_

#include <semanage/context_record.h>
#include <semanage/handle.h>
#include <stddef.h>

#ifndef _SEMANAGE_IBENDPORT_DEFINED_
struct semanage_ibendport;
struct semanage_ibendport_key;
typedef struct semanage_ibendport semanage_ibendport_t;
typedef struct semanage_ibendport_key semanage_ibendport_key_t;
#define _SEMANAGE_IBENDPORT_DEFINED_
#endif

extern int semanage_ibendport_compare(const semanage_ibendport_t *ibendport,
				      const semanage_ibendport_key_t *key);

extern int semanage_ibendport_compare2(const semanage_ibendport_t *ibendport,
				       const semanage_ibendport_t *ibendport2);

extern int semanage_ibendport_key_create(semanage_handle_t *handle,
					 const char *ibdev_name,
					 int port,
					 semanage_ibendport_key_t **key_ptr);

extern int semanage_ibendport_key_extract(semanage_handle_t *handle,
					  const semanage_ibendport_t *ibendport,
					  semanage_ibendport_key_t **key_ptr);

extern void semanage_ibendport_key_free(semanage_ibendport_key_t *key);

extern int semanage_ibendport_get_ibdev_name(semanage_handle_t *handle,
					     const semanage_ibendport_t *ibendport,
					     char **ibdev_name_ptr);

extern int semanage_ibendport_set_ibdev_name(semanage_handle_t *handle,
					     semanage_ibendport_t *ibendport,
					     const char *ibdev_name);

extern int semanage_ibendport_get_port(const semanage_ibendport_t *ibendport);

extern void semanage_ibendport_set_port(semanage_ibendport_t *ibendport, int port);

extern semanage_context_t *semanage_ibendport_get_con(const semanage_ibendport_t *ibendport);

extern int semanage_ibendport_set_con(semanage_handle_t *handle,
				      semanage_ibendport_t *ibendport,
				      semanage_context_t *con);

extern int semanage_ibendport_create(semanage_handle_t *handle,
				     semanage_ibendport_t **ibendport_ptr);

extern int semanage_ibendport_clone(semanage_handle_t *handle,
				    const semanage_ibendport_t *ibendport,
				    semanage_ibendport_t **ibendport_ptr);

extern void semanage_ibendport_free(semanage_ibendport_t *ibendport);

#endif
