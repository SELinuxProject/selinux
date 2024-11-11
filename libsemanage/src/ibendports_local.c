/* Copyright (C) 2017 Mellanox Technologies Inc */

struct semanage_ibendport;
struct semanage_ibendport_key;
typedef struct semanage_ibendport_key record_key_t;
typedef struct semanage_ibendport record_t;
#define DBASE_RECORD_DEFINED

#include <stdlib.h>
#include <string.h>
#include <sepol/policydb.h>
#include "ibendport_internal.h"
#include "debug.h"
#include "handle.h"
#include "database.h"

int semanage_ibendport_modify_local(semanage_handle_t *handle,
				    const semanage_ibendport_key_t *key,
				    const semanage_ibendport_t *data)
{
	dbase_config_t *dconfig = semanage_ibendport_dbase_local(handle);

	return dbase_modify(handle, dconfig, key, data);
}

int semanage_ibendport_del_local(semanage_handle_t *handle,
				 const semanage_ibendport_key_t *key)
{
	dbase_config_t *dconfig = semanage_ibendport_dbase_local(handle);

	return dbase_del(handle, dconfig, key);
}

int semanage_ibendport_query_local(semanage_handle_t *handle,
				   const semanage_ibendport_key_t *key,
				   semanage_ibendport_t **response)
{
	dbase_config_t *dconfig = semanage_ibendport_dbase_local(handle);

	return dbase_query(handle, dconfig, key, response);
}

int semanage_ibendport_exists_local(semanage_handle_t *handle,
				    const semanage_ibendport_key_t *key,
				    int *response)
{
	dbase_config_t *dconfig = semanage_ibendport_dbase_local(handle);

	return dbase_exists(handle, dconfig, key, response);
}

int semanage_ibendport_count_local(semanage_handle_t *handle,
				   unsigned int *response)
{
	dbase_config_t *dconfig = semanage_ibendport_dbase_local(handle);

	return dbase_count(handle, dconfig, response);
}

int semanage_ibendport_iterate_local(semanage_handle_t *handle,
				     int (*handler)(const semanage_ibendport_t *record,
						    void *varg), void *handler_arg)
{
	dbase_config_t *dconfig = semanage_ibendport_dbase_local(handle);
	return dbase_iterate(handle, dconfig, handler, handler_arg);
}

int semanage_ibendport_list_local(semanage_handle_t *handle,
				  semanage_ibendport_t ***records,
				  unsigned int *count)
{
	dbase_config_t *dconfig = semanage_ibendport_dbase_local(handle);

	return dbase_list(handle, dconfig, records, count);
}


int semanage_ibendport_validate_local(semanage_handle_t *handle)
{
	semanage_ibendport_t **ibendports = NULL;
	unsigned int nibendports = 0;
	unsigned int i = 0, j = 0;
	char *ibdev_name = NULL;
	char *ibdev_name2 = NULL;
	int port;
	int port2;

	/* List and sort the ibendports */
	if (semanage_ibendport_list_local(handle, &ibendports, &nibendports) < 0)
		goto err;

	if (nibendports > 1)
		qsort(ibendports, nibendports, sizeof(semanage_ibendport_t *), semanage_ibendport_compare2_qsort);

	/* Test each ibendport */
	while (i < nibendports) {
		int stop = 0;

		free(ibdev_name);
		ibdev_name = NULL;
		if (STATUS_SUCCESS !=
				semanage_ibendport_get_ibdev_name(handle,
								  ibendports[i],
								  &ibdev_name)) {
			ERR(handle, "Couldn't get IB device name");
			goto err;
		}

		port = semanage_ibendport_get_port(ibendports[i]);

		/* Find the first ibendport with matching
		 * ibdev_name to compare against
		 */
		do {
			if (j == nibendports - 1)
				goto next;
			j++;
			free(ibdev_name2);
			ibdev_name2 = NULL;
			if (STATUS_SUCCESS !=
				semanage_ibendport_get_ibdev_name(handle,
								  ibendports[j],
								  &ibdev_name2)) {
				ERR(handle, "Couldn't get IB device name.");
				goto err;
			}
			port2 = semanage_ibendport_get_port(ibendports[j]);

			stop = !strcmp(ibdev_name, ibdev_name2);
		} while (!stop);

		if (port == port2) {
			ERR(handle, "ibendport %s/%u already exists.",
			    ibdev_name2, port2);
			goto invalid;
		}
next:
		i++;
		j = i;
	}

	free(ibdev_name);
	free(ibdev_name2);
	for (i = 0; i < nibendports; i++)
		semanage_ibendport_free(ibendports[i]);
	free(ibendports);
	return STATUS_SUCCESS;

err:
	ERR(handle, "could not complete ibendports validity check");

invalid:
	free(ibdev_name);
	free(ibdev_name2);
	for (i = 0; i < nibendports; i++)
		semanage_ibendport_free(ibendports[i]);
	free(ibendports);
	return STATUS_ERR;
}
