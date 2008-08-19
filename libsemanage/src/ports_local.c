/* Copyright (C) 2005 Red Hat, Inc. */

struct semanage_port;
struct semanage_port_key;
typedef struct semanage_port_key record_key_t;
typedef struct semanage_port record_t;
#define DBASE_RECORD_DEFINED

#include <stdlib.h>
#include "port_internal.h"
#include "debug.h"
#include "handle.h"
#include "database.h"

int semanage_port_modify_local(semanage_handle_t * handle,
			       const semanage_port_key_t * key,
			       const semanage_port_t * data)
{

	dbase_config_t *dconfig = semanage_port_dbase_local(handle);
	return dbase_modify(handle, dconfig, key, data);
}

int semanage_port_del_local(semanage_handle_t * handle,
			    const semanage_port_key_t * key)
{

	dbase_config_t *dconfig = semanage_port_dbase_local(handle);
	return dbase_del(handle, dconfig, key);
}

int semanage_port_query_local(semanage_handle_t * handle,
			      const semanage_port_key_t * key,
			      semanage_port_t ** response)
{

	dbase_config_t *dconfig = semanage_port_dbase_local(handle);
	return dbase_query(handle, dconfig, key, response);
}

int semanage_port_exists_local(semanage_handle_t * handle,
			       const semanage_port_key_t * key, int *response)
{

	dbase_config_t *dconfig = semanage_port_dbase_local(handle);
	return dbase_exists(handle, dconfig, key, response);
}

int semanage_port_count_local(semanage_handle_t * handle,
			      unsigned int *response)
{

	dbase_config_t *dconfig = semanage_port_dbase_local(handle);
	return dbase_count(handle, dconfig, response);
}

int semanage_port_iterate_local(semanage_handle_t * handle,
				int (*handler) (const semanage_port_t * record,
						void *varg), void *handler_arg)
{

	dbase_config_t *dconfig = semanage_port_dbase_local(handle);
	return dbase_iterate(handle, dconfig, handler, handler_arg);
}

int semanage_port_list_local(semanage_handle_t * handle,
			     semanage_port_t *** records, unsigned int *count)
{

	dbase_config_t *dconfig = semanage_port_dbase_local(handle);
	return dbase_list(handle, dconfig, records, count);
}

hidden_def(semanage_port_list_local)

int hidden semanage_port_validate_local(semanage_handle_t * handle)
{

	semanage_port_t **ports = NULL;
	unsigned int nports = 0;
	unsigned int i = 0, j = 0;

	/* List and sort the ports */
	if (semanage_port_list_local(handle, &ports, &nports) < 0)
		goto err;
	qsort(ports, nports, sizeof(semanage_port_t *),
	      (int (*)(const void *, const void *))
	      &semanage_port_compare2_qsort);

	/* Test each port for overlap */
	while (i < nports) {

		int proto = semanage_port_get_proto(ports[i]);
		int low = semanage_port_get_low(ports[i]);
		int high = semanage_port_get_high(ports[i]);
		const char *proto_str = semanage_port_get_proto_str(proto);

		const char *proto_str2;
		int proto2, low2, high2;

		/* Find the first port with matching 
		   protocol to compare against */
		do {
			if (j == nports - 1)
				goto next;
			j++;
			proto2 = semanage_port_get_proto(ports[j]);
			low2 = semanage_port_get_low(ports[j]);
			high2 = semanage_port_get_high(ports[j]);
			proto_str2 = semanage_port_get_proto_str(proto2);

		} while (proto != proto2);

		/* Overlap detected */
		if (low2 <= high) {
			ERR(handle, "port overlap between ranges "
			    "%u - %u (%s) <--> %u - %u (%s).",
			    low, high, proto_str, low2, high2, proto_str2);
			goto invalid;
		}

		/* If closest port of matching protocol doesn't overlap with
		 * test port, neither do the rest of them, because that's 
		 * how the sort function works on ports - lower bound 
		 * ports come first */
	      next:
		i++;
		j = i;
	}

	for (i = 0; i < nports; i++)
		semanage_port_free(ports[i]);
	free(ports);
	return STATUS_SUCCESS;

      err:
	ERR(handle, "could not complete ports validity check");

      invalid:
	for (i = 0; i < nports; i++)
		semanage_port_free(ports[i]);
	free(ports);
	return STATUS_ERR;
}
