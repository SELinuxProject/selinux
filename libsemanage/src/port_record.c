/* Copyright (C) 2005 Red Hat, Inc. */

/* Object: semanage_port_t (Network Port)
 * Object: semanage_port_key_t (Network Port Key)
 * Implements: record_t (Database Record)
 * Implements: record_key_t (Database Record Key)
 */

#include <sepol/context_record.h>
#include <sepol/port_record.h>

typedef sepol_context_t semanage_context_t;
typedef sepol_port_t semanage_port_t;
typedef sepol_port_key_t semanage_port_key_t;
#define _SEMANAGE_PORT_DEFINED_
#define _SEMANAGE_CONTEXT_DEFINED_

typedef semanage_port_t record_t;
typedef semanage_port_key_t record_key_t;
#define DBASE_RECORD_DEFINED

#include "port_internal.h"
#include "handle.h"
#include "database.h"

/* Key */
int semanage_port_compare(const semanage_port_t * port,
			  const semanage_port_key_t * key)
{

	return sepol_port_compare(port, key);
}

hidden_def(semanage_port_compare)

int semanage_port_compare2(const semanage_port_t * port,
			   const semanage_port_t * port2)
{

	return sepol_port_compare2(port, port2);
}

hidden_def(semanage_port_compare2)

hidden int semanage_port_compare2_qsort(const semanage_port_t ** port,
					const semanage_port_t ** port2)
{

	return sepol_port_compare2(*port, *port2);
}

int semanage_port_key_create(semanage_handle_t * handle,
			     int low, int high, int proto,
			     semanage_port_key_t ** key_ptr)
{

	return sepol_port_key_create(handle->sepolh, low, high, proto, key_ptr);
}

int semanage_port_key_extract(semanage_handle_t * handle,
			      const semanage_port_t * port,
			      semanage_port_key_t ** key_ptr)
{

	return sepol_port_key_extract(handle->sepolh, port, key_ptr);
}

hidden_def(semanage_port_key_extract)

void semanage_port_key_free(semanage_port_key_t * key)
{

	sepol_port_key_free(key);
}

hidden_def(semanage_port_key_free)

/* Protocol */
int semanage_port_get_proto(const semanage_port_t * port)
{

	return sepol_port_get_proto(port);
}

hidden_def(semanage_port_get_proto)

void semanage_port_set_proto(semanage_port_t * port, int proto)
{

	sepol_port_set_proto(port, proto);
}

hidden_def(semanage_port_set_proto)

const char *semanage_port_get_proto_str(int proto)
{

	return sepol_port_get_proto_str(proto);
}

hidden_def(semanage_port_get_proto_str)

/* Port */
int semanage_port_get_low(const semanage_port_t * port)
{

	return sepol_port_get_low(port);
}

hidden_def(semanage_port_get_low)

int semanage_port_get_high(const semanage_port_t * port)
{

	return sepol_port_get_high(port);
}

hidden_def(semanage_port_get_high)

void semanage_port_set_port(semanage_port_t * port, int port_num)
{

	sepol_port_set_port(port, port_num);
}

hidden_def(semanage_port_set_port)

void semanage_port_set_range(semanage_port_t * port, int low, int high)
{

	sepol_port_set_range(port, low, high);
}

hidden_def(semanage_port_set_range)

/* Context */
semanage_context_t *semanage_port_get_con(const semanage_port_t * port)
{

	return sepol_port_get_con(port);
}

hidden_def(semanage_port_get_con)

int semanage_port_set_con(semanage_handle_t * handle,
			  semanage_port_t * port, semanage_context_t * con)
{

	return sepol_port_set_con(handle->sepolh, port, con);
}

hidden_def(semanage_port_set_con)

/* Create/Clone/Destroy */
int semanage_port_create(semanage_handle_t * handle,
			 semanage_port_t ** port_ptr)
{

	return sepol_port_create(handle->sepolh, port_ptr);
}

hidden_def(semanage_port_create)

int semanage_port_clone(semanage_handle_t * handle,
			const semanage_port_t * port,
			semanage_port_t ** port_ptr)
{

	return sepol_port_clone(handle->sepolh, port, port_ptr);
}

hidden_def(semanage_port_clone)

void semanage_port_free(semanage_port_t * port)
{

	sepol_port_free(port);
}

hidden_def(semanage_port_free)

/* Port base functions */
record_table_t SEMANAGE_PORT_RTABLE = {
	.create = semanage_port_create,
	.key_extract = semanage_port_key_extract,
	.key_free = semanage_port_key_free,
	.clone = semanage_port_clone,
	.compare = semanage_port_compare,
	.compare2 = semanage_port_compare2,
	.compare2_qsort = semanage_port_compare2_qsort,
	.free = semanage_port_free,
};
