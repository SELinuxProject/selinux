/* Copyright (C) 2017 Mellanox Technologies Inc. */

struct semanage_ibpkey;
struct semanage_ibpkey_key;
typedef struct semanage_ibpkey_key record_key_t;
typedef struct semanage_ibpkey record_t;
#define DBASE_RECORD_DEFINED

#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include "ibpkey_internal.h"
#include "debug.h"
#include "handle.h"
#include "database.h"

int semanage_ibpkey_modify_local(semanage_handle_t *handle,
				 const semanage_ibpkey_key_t *key,
				 const semanage_ibpkey_t *data)
{
	dbase_config_t *dconfig = semanage_ibpkey_dbase_local(handle);

	return dbase_modify(handle, dconfig, key, data);
}

int semanage_ibpkey_del_local(semanage_handle_t *handle,
			      const semanage_ibpkey_key_t *key)
{
	dbase_config_t *dconfig = semanage_ibpkey_dbase_local(handle);

	return dbase_del(handle, dconfig, key);
}

int semanage_ibpkey_query_local(semanage_handle_t *handle,
				const semanage_ibpkey_key_t *key,
				semanage_ibpkey_t **response)
{
	dbase_config_t *dconfig = semanage_ibpkey_dbase_local(handle);

	return dbase_query(handle, dconfig, key, response);
}

int semanage_ibpkey_exists_local(semanage_handle_t *handle,
				 const semanage_ibpkey_key_t *key,
				 int *response)
{
	dbase_config_t *dconfig = semanage_ibpkey_dbase_local(handle);

	return dbase_exists(handle, dconfig, key, response);
}

int semanage_ibpkey_count_local(semanage_handle_t *handle,
				unsigned int *response)
{
	dbase_config_t *dconfig = semanage_ibpkey_dbase_local(handle);

	return dbase_count(handle, dconfig, response);
}

int semanage_ibpkey_iterate_local(semanage_handle_t *handle,
				  int (*handler)(const semanage_ibpkey_t *record,
						 void *varg), void *handler_arg)
{
	dbase_config_t *dconfig = semanage_ibpkey_dbase_local(handle);

	return dbase_iterate(handle, dconfig, handler, handler_arg);
}

int semanage_ibpkey_list_local(semanage_handle_t *handle,
			       semanage_ibpkey_t ***records, unsigned int *count)
{
	dbase_config_t *dconfig = semanage_ibpkey_dbase_local(handle);

	return dbase_list(handle, dconfig, records, count);
}


int semanage_ibpkey_validate_local(semanage_handle_t *handle)
{
	semanage_ibpkey_t **ibpkeys = NULL;
	unsigned int nibpkeys = 0;
	unsigned int i = 0, j = 0;
	uint64_t subnet_prefix;
	uint64_t subnet_prefix2;
	char *subnet_prefix_str;
	char *subnet_prefix_str2;
	int low, high;
	int low2, high2;

	/* List and sort the ibpkeys */
	if (semanage_ibpkey_list_local(handle, &ibpkeys, &nibpkeys) < 0)
		goto err;

	qsort(ibpkeys, nibpkeys, sizeof(semanage_ibpkey_t *),
	      (int (*)(const void *, const void *))
	      &semanage_ibpkey_compare2_qsort);

	/* Test each ibpkey for overlap */
	while (i < nibpkeys) {
		if (STATUS_SUCCESS != semanage_ibpkey_get_subnet_prefix(handle,
									ibpkeys[i],
									&subnet_prefix_str)) {
			ERR(handle, "Couldn't get subnet prefix string");
			goto err;
		}

		subnet_prefix = semanage_ibpkey_get_subnet_prefix_bytes(ibpkeys[i]);
		low = semanage_ibpkey_get_low(ibpkeys[i]);
		high = semanage_ibpkey_get_high(ibpkeys[i]);

		/* Find the first ibpkey with matching
		 * subnet_prefix to compare against
		 */
		do {
			if (j == nibpkeys - 1)
				goto next;
			j++;

			if (STATUS_SUCCESS !=
				semanage_ibpkey_get_subnet_prefix(handle,
								  ibpkeys[j],
								  &subnet_prefix_str2)) {
				ERR(handle, "Couldn't get subnet prefix string");
				goto err;
			}
			subnet_prefix2 = semanage_ibpkey_get_subnet_prefix_bytes(ibpkeys[j]);
			low2 = semanage_ibpkey_get_low(ibpkeys[j]);
			high2 = semanage_ibpkey_get_high(ibpkeys[j]);
		} while (subnet_prefix != subnet_prefix2);

		/* Overlap detected */
		if (low2 <= high) {
			ERR(handle, "ibpkey overlap between ranges "
			    "(%s) %u - %u <--> (%s) %u - %u.",
			    subnet_prefix_str, low, high,
			    subnet_prefix_str2, low2, high2);
			goto invalid;
		}

		/* If closest ibpkey of matching subnet prefix doesn't overlap
		 * with test ibpkey, neither do the rest of them, because that's
		 * how the sort function works on ibpkeys - lower bound
		 * ibpkeys come first
		 */
next:
		i++;
		j = i;
	}

	for (i = 0; i < nibpkeys; i++)
		semanage_ibpkey_free(ibpkeys[i]);
	free(ibpkeys);
	return STATUS_SUCCESS;

err:
	ERR(handle, "could not complete ibpkeys validity check");

invalid:
	for (i = 0; i < nibpkeys; i++)
		semanage_ibpkey_free(ibpkeys[i]);
	free(ibpkeys);
	return STATUS_ERR;
}
