struct semanage_fcontext;
struct semanage_fcontext_key;
typedef struct semanage_fcontext record_t;
typedef struct semanage_fcontext_key record_key_t;
#define DBASE_RECORD_DEFINED

#include <stdlib.h>
#include <string.h>
#include "fcontext_internal.h"
#include "debug.h"

struct semanage_fcontext {

	/* Matching expression */
	char *expr;

	/* Type of object */
	int type;

	/* Context */
	semanage_context_t *con;
};

struct semanage_fcontext_key {

	/* Matching expression */
	char *expr;

	/* Type of object */
	int type;
};

/* Key */
int semanage_fcontext_key_create(semanage_handle_t * handle,
				 const char *expr,
				 int type, semanage_fcontext_key_t ** key_ptr)
{

	semanage_fcontext_key_t *tmp_key =
	    (semanage_fcontext_key_t *) malloc(sizeof(semanage_fcontext_key_t));

	if (!tmp_key) {
		ERR(handle, "out of memory, could not "
		    "create file context key");
		return STATUS_ERR;
	}
	tmp_key->expr = strdup(expr);
	if (!tmp_key->expr) {
		ERR(handle, "out of memory, could not create file context key.");
		free(tmp_key);
		return STATUS_ERR;
	}
	tmp_key->type = type;

	*key_ptr = tmp_key;
	return STATUS_SUCCESS;
}


int semanage_fcontext_key_extract(semanage_handle_t * handle,
				  const semanage_fcontext_t * fcontext,
				  semanage_fcontext_key_t ** key_ptr)
{

	if (semanage_fcontext_key_create(handle, fcontext->expr,
					 fcontext->type, key_ptr) < 0) {
		ERR(handle, "could not extract key from "
		    "file context %s (%s)", fcontext->expr,
		    semanage_fcontext_get_type_str(fcontext->type));
		return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}


void semanage_fcontext_key_free(semanage_fcontext_key_t * key)
{
	free(key->expr);
	free(key);
}


int semanage_fcontext_compare(const semanage_fcontext_t * fcontext,
			      const semanage_fcontext_key_t * key)
{

	int rv = strcmp(fcontext->expr, key->expr);
	if (rv != 0)
		return rv;
	else {
		if (fcontext->type < key->type)
			return -1;

		else if (key->type < fcontext->type)
			return 1;

		else
			return 0;
	}
}


int semanage_fcontext_compare2(const semanage_fcontext_t * fcontext,
			       const semanage_fcontext_t * fcontext2)
{

	int rv = strcmp(fcontext->expr, fcontext2->expr);
	if (rv != 0)
		return rv;
	else {
		if (fcontext->type < fcontext2->type)
			return -1;

		else if (fcontext2->type < fcontext->type)
			return 1;

		else
			return 0;
	}
}


static int semanage_fcontext_compare2_qsort(const semanage_fcontext_t **
					    fcontext,
					    const semanage_fcontext_t **
					    fcontext2)
{

	return semanage_fcontext_compare2(*fcontext, *fcontext2);
}

/* Create */
int semanage_fcontext_create(semanage_handle_t * handle,
			     semanage_fcontext_t ** fcontext)
{

	semanage_fcontext_t *tmp_fcontext =
	    (semanage_fcontext_t *) malloc(sizeof(semanage_fcontext_t));

	if (!tmp_fcontext) {
		ERR(handle, "out of memory, could not create "
		    "file context record");
		return STATUS_ERR;
	}

	tmp_fcontext->expr = NULL;
	tmp_fcontext->type = SEMANAGE_FCONTEXT_ALL;
	tmp_fcontext->con = NULL;
	*fcontext = tmp_fcontext;

	return STATUS_SUCCESS;
}


/* Regexp */
const char *semanage_fcontext_get_expr(const semanage_fcontext_t * fcontext)
{

	return fcontext->expr;
}


int semanage_fcontext_set_expr(semanage_handle_t * handle,
			       semanage_fcontext_t * fcontext, const char *expr)
{

	char *tmp_expr = strdup(expr);
	if (!tmp_expr) {
		ERR(handle, "out of memory, " "could not set regexp string");
		return STATUS_ERR;
	}
	free(fcontext->expr);
	fcontext->expr = tmp_expr;
	return STATUS_SUCCESS;
}


/* Type */
int semanage_fcontext_get_type(const semanage_fcontext_t * fcontext)
{

	return fcontext->type;
}


const char *semanage_fcontext_get_type_str(int type)
{

	switch (type) {
	case SEMANAGE_FCONTEXT_ALL:
		return "all files";
	case SEMANAGE_FCONTEXT_REG:
		return "regular file";
	case SEMANAGE_FCONTEXT_DIR:
		return "directory";
	case SEMANAGE_FCONTEXT_CHAR:
		return "character device";
	case SEMANAGE_FCONTEXT_BLOCK:
		return "block device";
	case SEMANAGE_FCONTEXT_SOCK:
		return "socket";
	case SEMANAGE_FCONTEXT_LINK:
		return "symbolic link";
	case SEMANAGE_FCONTEXT_PIPE:
		return "named pipe";
	default:
		return "????";
	}
}


void semanage_fcontext_set_type(semanage_fcontext_t * fcontext, int type)
{

	fcontext->type = type;
}


/* Context */
semanage_context_t *semanage_fcontext_get_con(const semanage_fcontext_t *
					      fcontext)
{

	return fcontext->con;
}


int semanage_fcontext_set_con(semanage_handle_t * handle,
			      semanage_fcontext_t * fcontext,
			      semanage_context_t * con)
{

	semanage_context_t *newcon;

	if (semanage_context_clone(handle, con, &newcon) < 0) {
		ERR(handle, "out of memory, could not set file context");
		return STATUS_ERR;
	}

	semanage_context_free(fcontext->con);
	fcontext->con = newcon;
	return STATUS_SUCCESS;
}


/* Deep copy clone */
int semanage_fcontext_clone(semanage_handle_t * handle,
			    const semanage_fcontext_t * fcontext,
			    semanage_fcontext_t ** fcontext_ptr)
{

	semanage_fcontext_t *new_fcontext = NULL;
	if (semanage_fcontext_create(handle, &new_fcontext) < 0)
		goto err;

	if (semanage_fcontext_set_expr(handle, new_fcontext, fcontext->expr) <
	    0)
		goto err;

	new_fcontext->type = fcontext->type;

	if (fcontext->con &&
	    (semanage_context_clone(handle, fcontext->con, &new_fcontext->con) <
	     0))
		goto err;

	*fcontext_ptr = new_fcontext;
	return STATUS_SUCCESS;

      err:
	ERR(handle, "could not clone file context record");
	semanage_fcontext_free(new_fcontext);
	return STATUS_ERR;
}


/* Destroy */
void semanage_fcontext_free(semanage_fcontext_t * fcontext)
{

	if (!fcontext)
		return;

	free(fcontext->expr);
	semanage_context_free(fcontext->con);
	free(fcontext);
}


/* Record base functions */
record_table_t SEMANAGE_FCONTEXT_RTABLE = {
	.create = semanage_fcontext_create,
	.key_extract = semanage_fcontext_key_extract,
	.key_free = semanage_fcontext_key_free,
	.clone = semanage_fcontext_clone,
	.compare = semanage_fcontext_compare,
	.compare2 = semanage_fcontext_compare2,
	.compare2_qsort = semanage_fcontext_compare2_qsort,
	.free = semanage_fcontext_free,
};
