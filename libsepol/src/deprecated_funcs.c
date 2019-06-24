#include <stdio.h>
#include "debug.h"

/*
 * Need to keep these stubs for the libsepol interfaces exported in
 * libsepol.map.in, as they are part of the shared library ABI.
 */

static const char *msg = "Deprecated interface";

/*
 * These two functions are deprecated and referenced in:
 *	include/libsepol/users.h
 */
int sepol_genusers(void *data __attribute((unused)),
		   size_t len __attribute((unused)),
		   const char *usersdir __attribute((unused)),
		   void **newdata __attribute((unused)),
		   size_t *newlen __attribute((unused)))
{
	WARN(NULL, "%s", msg);
	return -1;
}

void sepol_set_delusers(int on __attribute((unused)))
{
	WARN(NULL, "%s", msg);
}

/*
 * These two functions are deprecated and referenced in:
 *	include/libsepol/booleans.h
 */
int sepol_genbools(void *data __attribute((unused)),
		   size_t len __attribute((unused)),
		   const char *booleans __attribute((unused)))
{
	WARN(NULL, "%s", msg);
	return -1;
}

int sepol_genbools_array(void *data __attribute((unused)),
			 size_t len __attribute((unused)),
			 char **names __attribute((unused)),
			 int *values __attribute((unused)),
			 int nel __attribute((unused)))
{
	WARN(NULL, "%s", msg);
	return -1;
}
