/*Copyright (C) 2005 Red Hat, Inc. */

/*Object: semanage_ibendport_t (Infiniband Pkey)
 *Object: semanage_ibendport_key_t (Infiniband Pkey Key)
 *Implements: record_t (Database Record)
 *Implements: record_key_t (Database Record Key)
 */

#include <sepol/context_record.h>
#include <sepol/ibendport_record.h>

typedef sepol_context_t semanage_context_t;
typedef sepol_ibendport_t semanage_ibendport_t;
typedef sepol_ibendport_key_t semanage_ibendport_key_t;
#define _SEMANAGE_IBENDPORT_DEFINED_
#define _SEMANAGE_CONTEXT_DEFINED_

typedef semanage_ibendport_t record_t;
typedef semanage_ibendport_key_t record_key_t;
#define DBASE_RECORD_DEFINED

#include "ibendport_internal.h"
#include "handle.h"
#include "database.h"

int semanage_ibendport_compare(const semanage_ibendport_t *ibendport,
			       const semanage_ibendport_key_t *key)
{
	return sepol_ibendport_compare(ibendport, key);
}


int semanage_ibendport_compare2(const semanage_ibendport_t *ibendport,
				const semanage_ibendport_t *ibendport2)
{
	return sepol_ibendport_compare2(ibendport, ibendport2);
}


 int semanage_ibendport_compare2_qsort(const void *p1, const void *p2)
{
	const semanage_ibendport_t *const *ibendport1 = p1;
	const semanage_ibendport_t *const *ibendport2 = p2;

	return sepol_ibendport_compare2(*ibendport1, *ibendport2);
}

int semanage_ibendport_key_create(semanage_handle_t *handle,
				  const char *ibdev_name,
				  int port,
				  semanage_ibendport_key_t **key_ptr)
{
	return sepol_ibendport_key_create(handle->sepolh, ibdev_name, port, key_ptr);
}

int semanage_ibendport_key_extract(semanage_handle_t *handle,
				   const semanage_ibendport_t *ibendport,
				   semanage_ibendport_key_t **key_ptr)
{
	return sepol_ibendport_key_extract(handle->sepolh, ibendport, key_ptr);
}


void semanage_ibendport_key_free(semanage_ibendport_key_t *key)
{
	sepol_ibendport_key_free(key);
}


int semanage_ibendport_get_ibdev_name(semanage_handle_t *handle,
				      const semanage_ibendport_t *ibendport,
				      char **ibdev_name_ptr)
{
	return sepol_ibendport_get_ibdev_name(handle->sepolh, ibendport, ibdev_name_ptr);
}


int semanage_ibendport_set_ibdev_name(semanage_handle_t *handle,
				      semanage_ibendport_t *ibendport,
				      const char *ibdev_name)
{
	return sepol_ibendport_set_ibdev_name(handle->sepolh, ibendport, ibdev_name);
}


int semanage_ibendport_get_port(const semanage_ibendport_t *ibendport)
{
	return sepol_ibendport_get_port(ibendport);
}


void semanage_ibendport_set_port(semanage_ibendport_t *ibendport, int port)
{
	sepol_ibendport_set_port(ibendport, port);
}


semanage_context_t *semanage_ibendport_get_con(const semanage_ibendport_t *ibendport)
{
	return sepol_ibendport_get_con(ibendport);
}


int semanage_ibendport_set_con(semanage_handle_t *handle,
			       semanage_ibendport_t *ibendport,
			       semanage_context_t *con)
{
	return sepol_ibendport_set_con(handle->sepolh, ibendport, con);
}


int semanage_ibendport_create(semanage_handle_t *handle,
			      semanage_ibendport_t **ibendport_ptr)
{
	return sepol_ibendport_create(handle->sepolh, ibendport_ptr);
}


int semanage_ibendport_clone(semanage_handle_t *handle,
			     const semanage_ibendport_t *ibendport,
			     semanage_ibendport_t **ibendport_ptr)
{
	return sepol_ibendport_clone(handle->sepolh, ibendport, ibendport_ptr);
}


void semanage_ibendport_free(semanage_ibendport_t *ibendport)
{
	sepol_ibendport_free(ibendport);
}


/*key base functions */
const record_table_t SEMANAGE_IBENDPORT_RTABLE = {
	.create = semanage_ibendport_create,
	.key_extract = semanage_ibendport_key_extract,
	.key_free = semanage_ibendport_key_free,
	.clone = semanage_ibendport_clone,
	.compare = semanage_ibendport_compare,
	.compare2 = semanage_ibendport_compare2,
	.compare2_qsort = semanage_ibendport_compare2_qsort,
	.free = semanage_ibendport_free,
};
