/* Copyright (C) 2005 Red Hat, Inc. */

struct semanage_user;
struct semanage_user_key;
typedef struct semanage_user record_t;
typedef struct semanage_user_key record_key_t;
#define DBASE_RECORD_DEFINED

struct semanage_user_base;
struct semanage_user_extra;
typedef struct semanage_user_base record1_t;
typedef struct semanage_user_extra record2_t;
#define DBASE_RECORD_JOIN_DEFINED

struct dbase_join;
typedef struct dbase_join dbase_t;
#define DBASE_DEFINED

#include <semanage/handle.h>
#include "user_internal.h"
#include "database_join.h"
#include "debug.h"

/* USER record: JOIN extension: method table */
static const record_join_table_t SEMANAGE_USER_JOIN_RTABLE = {
	.join = semanage_user_join,
	.split = semanage_user_split,
};

int user_join_dbase_init(semanage_handle_t * handle,
			 dbase_config_t * join1,
			 dbase_config_t * join2, dbase_config_t * dconfig)
{

	if (dbase_join_init(handle,
			    &SEMANAGE_USER_RTABLE,
			    &SEMANAGE_USER_JOIN_RTABLE,
			    join1, join2, &dconfig->dbase) < 0)
		return STATUS_ERR;

	dconfig->dtable = &SEMANAGE_JOIN_DTABLE;
	return STATUS_SUCCESS;
}

void user_join_dbase_release(dbase_config_t * dconfig)
{

	dbase_join_release(dconfig->dbase);
}
