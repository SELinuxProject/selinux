/* Copyright (C) 2005 Red Hat, Inc. */

#ifndef _SEMANAGE_PORT_RECORD_H_
#define _SEMANAGE_PORT_RECORD_H_

#include <semanage/context_record.h>
#include <semanage/handle.h>

#ifndef _SEMANAGE_PORT_DEFINED_
struct semanage_port;
struct semanage_port_key;
typedef struct semanage_port semanage_port_t;
typedef struct semanage_port_key semanage_port_key_t;
#define _SEMANAGE_PORT_DEFINED_
#endif

#define SEMANAGE_PROTO_UDP 0
#define SEMANAGE_PROTO_TCP 1

/* Key */
extern int semanage_port_compare(const semanage_port_t * port,
				 const semanage_port_key_t * key);

extern int semanage_port_compare2(const semanage_port_t * port,
				  const semanage_port_t * port2);

extern int semanage_port_key_create(semanage_handle_t * handle,
				    int low, int high, int proto,
				    semanage_port_key_t ** key_ptr);

extern int semanage_port_key_extract(semanage_handle_t * handle,
				     const semanage_port_t * port,
				     semanage_port_key_t ** key_ptr);

extern void semanage_port_key_free(semanage_port_key_t * key);

/* Protocol */
extern int semanage_port_get_proto(const semanage_port_t * port);

extern void semanage_port_set_proto(semanage_port_t * port, int proto);

extern const char *semanage_port_get_proto_str(int proto);

/* Port */
extern int semanage_port_get_low(const semanage_port_t * port);

extern int semanage_port_get_high(const semanage_port_t * port);

extern void semanage_port_set_port(semanage_port_t * port, int port_num);

extern void semanage_port_set_range(semanage_port_t * port, int low, int high);

/* Context */
extern semanage_context_t *semanage_port_get_con(const semanage_port_t * port);

extern int semanage_port_set_con(semanage_handle_t * handle,
				 semanage_port_t * port,
				 semanage_context_t * con);

/* Create/Clone/Destroy */
extern int semanage_port_create(semanage_handle_t * handle,
				semanage_port_t ** port_ptr);

extern int semanage_port_clone(semanage_handle_t * handle,
			       const semanage_port_t * port,
			       semanage_port_t ** port_ptr);

extern void semanage_port_free(semanage_port_t * port);

#endif
