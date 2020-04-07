/* Author: Joshua Brindle <jbrindle@tresys.co
 *	   Jason Tang	  <jtang@tresys.com>
 *	   Caleb Case	  <ccase@tresys.com>
 *
 * Copyright (C) 2004-2005,2009 Tresys Technology, LLC
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

/* This file implements only the publicly-visible module functions to libsemanage. */

#include "direct_api.h"
#include "modules.h"
#include "semanage_conf.h"
#include "semanage_store.h"

#include <stdarg.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>

#include "handle.h"
#include "modules.h"
#include "debug.h"

asm(".symver semanage_module_get_enabled_1_1,semanage_module_get_enabled@@LIBSEMANAGE_1.1");
asm(".symver semanage_module_get_enabled_1_0,semanage_module_get_enabled@LIBSEMANAGE_1.0");
asm(".symver semanage_module_install_pp,semanage_module_install@LIBSEMANAGE_1.0");
asm(".symver semanage_module_install_hll,semanage_module_install@@LIBSEMANAGE_1.1");

/* Takes a module stored in 'module_data' and parses its headers.
 * Sets reference variables 'module_name' to module's name and
 * 'version' to module's version. The caller is responsible for
 * free()ing 'module_name' and 'version'; they will be
 * set to NULL upon entering this function.  Returns 0 on success, -1
 * if out of memory, or -2 if data did not represent a module.
 */
static int parse_module_headers(semanage_handle_t * sh, char *module_data,
				size_t data_len, char **module_name, char **version)
{
	struct sepol_policy_file *pf;
	int file_type;
	*version = NULL;

	if (sepol_policy_file_create(&pf)) {
		ERR(sh, "Out of memory!");
		return -1;
	}
	sepol_policy_file_set_mem(pf, module_data, data_len);
	sepol_policy_file_set_handle(pf, sh->sepolh);
	if (module_data == NULL ||
	    data_len == 0 ||
	    sepol_module_package_info(pf, &file_type, module_name, version) == -1) {
		sepol_policy_file_free(pf);
		ERR(sh, "Could not parse module data.");
		return -2;
	}
	sepol_policy_file_free(pf);
	if (file_type != SEPOL_POLICY_MOD) {
		ERR(sh, "Data did not represent a pp module. Please upgrade to the latest version of libsemanage to support hll modules.");
		return -2;
	}

	return 0;
}

/* This function is used to preserve ABI compatibility with
 * versions of semodule using LIBSEMANAGE_1.0
 */
int semanage_module_install_pp(semanage_handle_t * sh,
			    char *module_data, size_t data_len)
{
	char *name = NULL;
	char *version = NULL;
	int status;

	if ((status = parse_module_headers(sh, module_data, data_len, &name, &version)) != 0) {
		goto cleanup;
	}

	status = semanage_module_install_hll(sh, module_data, data_len, name, "pp");

cleanup:
	free(name);
	free(version);
	return status;
}

int semanage_module_install_hll(semanage_handle_t * sh,
			    char *module_data, size_t data_len, const char *name, const char *ext_lang)
{
	if (sh->funcs->install == NULL) {
		ERR(sh,
		    "No install function defined for this connection type.");
		return -1;
	} else if (!sh->is_connected) {
		ERR(sh, "Not connected.");
		return -1;
	} else if (!sh->is_in_transaction) {
		if (semanage_begin_transaction(sh) < 0) {
			return -1;
		}
	}
	sh->modules_modified = 1;
	return sh->funcs->install(sh, module_data, data_len, name, ext_lang);
}

int semanage_module_install_file(semanage_handle_t * sh,
				 const char *module_name) {

	if (sh->funcs->install_file == NULL) {
		ERR(sh,
		    "No install function defined for this connection type.");
		return -1;
	} else if (!sh->is_connected) {
		ERR(sh, "Not connected.");
		return -1;
	} else if (!sh->is_in_transaction) {
		if (semanage_begin_transaction(sh) < 0) {
			return -1;
		}
	}
	sh->modules_modified = 1;
	return sh->funcs->install_file(sh, module_name);
}

int semanage_module_extract(semanage_handle_t * sh,
				 semanage_module_key_t *modkey,
				 int extract_cil,
				 void **mapped_data,
				 size_t *data_len,
				 semanage_module_info_t **modinfo) {
	if (sh->funcs->extract == NULL) {
		ERR(sh,
		    "No get function defined for this connection type.");
		return -1;
	} else if (!sh->is_connected) {
		ERR(sh, "Not connected.");
		return -1;
	}
	return sh->funcs->extract(sh, modkey, extract_cil, mapped_data, data_len, modinfo);
}

/* Legacy function that remains to preserve ABI
 * compatibility. Please use semanage_module_install instead.
 */
int semanage_module_upgrade(semanage_handle_t * sh,
			    char *module_data, size_t data_len)
{
	return semanage_module_install_pp(sh, module_data, data_len);
	
}

/* Legacy function that remains to preserve ABI
 * compatibility. Please use semanage_module_install_file instead.
 */
int semanage_module_upgrade_file(semanage_handle_t * sh,
				 const char *module_name)
{
	return semanage_module_install_file(sh, module_name);
}

/* Legacy function that remains to preserve ABI
 * compatibility. Please use semanage_module_install instead.
 */
int semanage_module_install_base(semanage_handle_t * sh,
				 char *module_data, size_t data_len)
{
	return semanage_module_install_pp(sh, module_data, data_len);
}

/* Legacy function that remains to preserve ABI
 * compatibility. Please use semanage_module_install_file instead.
 */
int semanage_module_install_base_file(semanage_handle_t * sh,
				 const char *module_name)
{
	return semanage_module_install_file(sh, module_name);
}

int semanage_module_remove(semanage_handle_t * sh, char *module_name)
{
	if (sh->funcs->remove == NULL) {
		ERR(sh, "No remove function defined for this connection type.");
		return -1;
	} else if (!sh->is_connected) {
		ERR(sh, "Not connected.");
		return -1;
	} else if (!sh->is_in_transaction) {
		if (semanage_begin_transaction(sh) < 0) {
			return -1;
		}
	}
	sh->modules_modified = 1;
	return sh->funcs->remove(sh, module_name);
}

int semanage_module_list(semanage_handle_t * sh,
			 semanage_module_info_t ** modinfo, int *num_modules)
{
	if (sh->funcs->list == NULL) {
		ERR(sh, "No list function defined for this connection type.");
		return -1;
	} else if (!sh->is_connected) {
		ERR(sh, "Not connected.");
		return -1;
	}
	return sh->funcs->list(sh, modinfo, num_modules);
}

void semanage_module_info_datum_destroy(semanage_module_info_t * modinfo)
{
	if (modinfo != NULL) {
		modinfo->priority = 0;

		free(modinfo->name);
		modinfo->name = NULL;

		free(modinfo->lang_ext);
		modinfo->lang_ext = NULL;

		modinfo->enabled = -1;
	}
}


semanage_module_info_t *semanage_module_list_nth(semanage_module_info_t * list,
						 int n)
{
	return list + n;
}


const char *semanage_module_get_name(semanage_module_info_t * modinfo)
{
	return modinfo->name;
}


/* Legacy function that remains to preserve ABI
 * compatibility.
 */
const char *semanage_module_get_version(semanage_module_info_t * modinfo
				__attribute__ ((unused)))
{
	return "";
}

int semanage_module_info_create(semanage_handle_t *sh,
				semanage_module_info_t **modinfo)
{
	assert(sh);
	assert(modinfo);

	*modinfo = malloc(sizeof(semanage_module_info_t));
	if (*modinfo == NULL) return -1;

	return semanage_module_info_init(sh, *modinfo);
}


int semanage_module_info_destroy(semanage_handle_t *sh,
				 semanage_module_info_t *modinfo)
{
	assert(sh);

	if (!modinfo) {
		return 0;
	}

	free(modinfo->name);
	free(modinfo->lang_ext);

	return semanage_module_info_init(sh, modinfo);
}


int semanage_module_info_init(semanage_handle_t *sh,
			      semanage_module_info_t *modinfo)
{
	assert(sh);
	assert(modinfo);

	modinfo->priority = 0;
	modinfo->name = NULL;
	modinfo->lang_ext = NULL;
	modinfo->enabled = -1;

	return 0;
}

int semanage_module_info_clone(semanage_handle_t *sh,
			       const semanage_module_info_t *source,
			       semanage_module_info_t *target)
{
	assert(sh);
	assert(source);
	assert(target);

	int status = 0;
	int ret = 0;

	ret = semanage_module_info_destroy(sh, target);
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

	ret = semanage_module_info_set_priority(sh, target, source->priority);
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

	ret = semanage_module_info_set_name(sh, target, source->name);
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

	ret = semanage_module_info_set_lang_ext(sh, target, source->lang_ext);
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

	ret = semanage_module_info_set_enabled(sh, target, source->enabled);
	if (ret != 0) {
		status = -1;
		goto cleanup;
	}

cleanup:
	if (status != 0) semanage_module_info_destroy(sh, target);
	return status;
}

int semanage_module_info_get_priority(semanage_handle_t *sh,
				      semanage_module_info_t *modinfo,
				      uint16_t *priority)
{
	assert(sh);
	assert(modinfo);
	assert(priority);

	*priority = modinfo->priority;

	return 0;
}


int semanage_module_info_get_name(semanage_handle_t *sh,
				  semanage_module_info_t *modinfo,
				  const char **name)
{
	assert(sh);
	assert(modinfo);
	assert(name);

	*name = modinfo->name;

	return 0;
}


int semanage_module_info_get_lang_ext(semanage_handle_t *sh,
				      semanage_module_info_t *modinfo,
				      const char **lang_ext)
{
	assert(sh);
	assert(modinfo);
	assert(lang_ext);

	*lang_ext = modinfo->lang_ext;

	return 0;
}


int semanage_module_info_get_enabled(semanage_handle_t *sh,
				     semanage_module_info_t *modinfo,
				     int *enabled)
{
	assert(sh);
	assert(modinfo);
	assert(enabled);

	*enabled = modinfo->enabled;

	return 0;
}


int semanage_module_info_set_priority(semanage_handle_t *sh,
				      semanage_module_info_t *modinfo,
				      uint16_t priority)
{
	assert(sh);
	assert(modinfo);

	/* Verify priority */
	if (semanage_module_validate_priority(priority) < 0) {
		errno = 0;
		ERR(sh, "Priority %d is invalid.", priority);
		return -1;
	}

	modinfo->priority = priority;

	return 0;
}


int semanage_module_info_set_name(semanage_handle_t *sh,
				  semanage_module_info_t *modinfo,
				  const char *name)
{
	assert(sh);
	assert(modinfo);
	assert(name);

	char * tmp;

	/* Verify name */
	if (semanage_module_validate_name(name) < 0) {
		errno = 0;
		ERR(sh, "Name %s is invalid.", name);
		return -1;
	}

	tmp = strdup(name);
	if (!tmp) {
		ERR(sh, "No memory available for strdup");
		return -1;
	}

	free(modinfo->name);
	modinfo->name = tmp;

	return 0;
}


int semanage_module_info_set_lang_ext(semanage_handle_t *sh,
				      semanage_module_info_t *modinfo,
				      const char *lang_ext)
{
	assert(sh);
	assert(modinfo);
	assert(lang_ext);

	char * tmp;

	/* Verify extension */
	if (semanage_module_validate_lang_ext(lang_ext) < 0) {
		errno = 0;
		ERR(sh, "Language extensions %s is invalid.", lang_ext);
		return -1;
	}

	tmp = strdup(lang_ext);
	if (!tmp) {
		ERR(sh, "No memory available for strdup");
		return -1;
	}

	free(modinfo->lang_ext);
	modinfo->lang_ext = tmp;

	return 0;
}


int semanage_module_info_set_enabled(semanage_handle_t *sh,
				     semanage_module_info_t *modinfo,
				     int enabled)
{
	assert(sh);
	assert(modinfo);

	/* Verify enabled */
	if (semanage_module_validate_enabled(enabled) < 0) {
		errno = 0;
		ERR(sh, "Enabled status %d is invalid.", enabled);
		return -1;
	}

	modinfo->enabled = enabled;

	return 0;
}


int semanage_module_get_path(semanage_handle_t *sh,
			     const semanage_module_info_t *modinfo,
			     enum semanage_module_path_type type,
			     char *path,
			     size_t len)
{
	assert(sh);
	assert(modinfo);
	assert(path);

	int status = 0;
	int ret = 0;

	const char *modules_path = NULL;
	const char *file = NULL;

	modules_path = sh->is_in_transaction ?
		semanage_path(SEMANAGE_TMP, SEMANAGE_MODULES):
		semanage_path(SEMANAGE_ACTIVE, SEMANAGE_MODULES);

	switch (type) {
		case SEMANAGE_MODULE_PATH_PRIORITY:
			/* verify priority */
			ret = semanage_module_validate_priority(modinfo->priority);
			if (ret < 0) {
				errno = 0;
				ERR(sh,
				    "Priority %d is invalid.",
				    modinfo->priority);
				status = ret;
				goto cleanup;
			}

			ret = snprintf(path,
				       len,
				       "%s/%03u",
				       modules_path,
				       modinfo->priority);
			if (ret < 0 || (size_t)ret >= len) {
				ERR(sh, "Unable to compose priority path.");
				status = -1;
				goto cleanup;
			}
			break;
		case SEMANAGE_MODULE_PATH_NAME:
			/* verify priority and name */
			ret = semanage_module_validate_priority(modinfo->priority);
			if (ret < 0) {
				errno = 0;
				ERR(sh,
				    "Priority %d is invalid.",
				    modinfo->priority);
				status = -1;
				goto cleanup;
			}

			ret = semanage_module_validate_name(modinfo->name);
			if (ret < 0) {
				errno = 0;
				ERR(sh, "Name %s is invalid.", modinfo->name);
				status = -1;
				goto cleanup;
			}

			ret = snprintf(path,
				       len,
				       "%s/%03u/%s",
				       modules_path,
				       modinfo->priority,
				       modinfo->name);
			if (ret < 0 || (size_t)ret >= len) {
				ERR(sh, "Unable to compose name path.");
				status = -1;
				goto cleanup;
			}
			break;
		case SEMANAGE_MODULE_PATH_HLL:
			if (file == NULL) file = "hll";
			/* FALLTHRU */
		case SEMANAGE_MODULE_PATH_CIL:
			if (file == NULL) file = "cil";
			/* FALLTHRU */
		case SEMANAGE_MODULE_PATH_LANG_EXT:
			if (file == NULL) file = "lang_ext";

			/* verify priority and name */
			ret = semanage_module_validate_priority(modinfo->priority);
			if (ret < 0) {
				errno = 0;
				ERR(sh,
				    "Priority %d is invalid.",
				    modinfo->priority);
				status = -1;
				goto cleanup;
			}

			ret = semanage_module_validate_name(modinfo->name);
			if (ret < 0) {
				errno = 0;
				ERR(sh, "Name %s is invalid.", modinfo->name);
				status = -1;
				goto cleanup;
			}

			ret = snprintf(path,
				       len,
				       "%s/%03u/%s/%s",
				       modules_path,
				       modinfo->priority,
				       modinfo->name,
				       file);
			if (ret < 0 || (size_t)ret >= len) {
				ERR(sh,
				    "Unable to compose path for %s file.",
				    file);
				status = -1;
				goto cleanup;
			}
			break;
		case SEMANAGE_MODULE_PATH_DISABLED:
			/* verify name */
			ret = semanage_module_validate_name(modinfo->name);
			if (ret < 0) {
				errno = 0;
				ERR(sh, "Name %s is invalid.", modinfo->name);
				status = -1;
				goto cleanup;
			}

			ret = snprintf(path,
				       len,
				       "%s/disabled/%s",
				       modules_path,
				       modinfo->name);
			if (ret < 0 || (size_t)ret >= len) {
				ERR(sh,
				    "Unable to compose disabled status path.");
				status = -1;
				goto cleanup;
			}
			break;
		default:
			ERR(sh, "Invalid module path type %d.", type);
			status = -1;
			goto cleanup;
	}

cleanup:
	return status;
}

int semanage_module_key_create(semanage_handle_t *sh,
			       semanage_module_key_t **modkey)
{
	assert(sh);
	assert(modkey);

	*modkey = malloc(sizeof(semanage_module_key_t));
	if (*modkey == NULL) return -1;

	return semanage_module_key_init(sh, *modkey);
}


int semanage_module_key_destroy(semanage_handle_t *sh,
				semanage_module_key_t *modkey)
{
	assert(sh);

	if (!modkey) {
		return 0;
	}

	free(modkey->name);

	return semanage_module_key_init(sh, modkey);
}


int semanage_module_key_init(semanage_handle_t *sh,
			     semanage_module_key_t *modkey)
{
	assert(sh);
	assert(modkey);

	modkey->name = NULL;
	modkey->priority = 0;

	return 0;
}

int semanage_module_key_get_name(semanage_handle_t *sh,
				 semanage_module_key_t *modkey,
				 const char **name)
{
	assert(sh);
	assert(modkey);
	assert(name);

	*name = modkey->name;

	return 0;
}


int semanage_module_key_get_priority(semanage_handle_t *sh,
				     semanage_module_key_t *modkey,
				     uint16_t *priority)
{
	assert(sh);
	assert(modkey);
	assert(priority);

	*priority = modkey->priority;

	return 0;
}


int semanage_module_key_set_name(semanage_handle_t *sh,
				 semanage_module_key_t *modkey,
				 const char *name)
{
	assert(sh);
	assert(modkey);
	assert(name);

	int status = 0;
	char *tmp = NULL;

	if (semanage_module_validate_name(name) < 0) {
		errno = 0;
		ERR(sh, "Name %s is invalid.", name);
		return -1;
	}

	tmp = strdup(name);
	if (tmp == NULL) {
		ERR(sh, "No memory available for strdup");
		status = -1;
		goto cleanup;
	}

	free(modkey->name);
	modkey->name = tmp;

cleanup:
	return status;
}


int semanage_module_key_set_priority(semanage_handle_t *sh,
				     semanage_module_key_t *modkey,
				     uint16_t priority)
{
	assert(sh);
	assert(modkey);

	if (semanage_module_validate_priority(priority) < 0) {
		errno = 0;
		ERR(sh, "Priority %d is invalid.", priority);
		return -1;
	}

	modkey->priority = priority;

	return 0;
}


int semanage_module_get_enabled_1_1(semanage_handle_t *sh,
				const semanage_module_key_t *modkey,
				int *enabled)
{
	assert(sh);
	assert(modkey);
	assert(enabled);

	if (sh->funcs->get_enabled == NULL) {
		ERR(sh,
		    "No get_enabled function defined for this connection type.");
		return -1;
	} else if (!sh->is_connected) {
		ERR(sh, "Not connected.");
		return -1;
	}

	return sh->funcs->get_enabled(sh, modkey, enabled);
}

int semanage_module_get_enabled_1_0(semanage_module_info_t *modinfo)
{
	return modinfo->enabled;
}

int semanage_module_set_enabled(semanage_handle_t *sh,
				const semanage_module_key_t *modkey,
				int enabled)
{
	assert(sh);
	assert(modkey);

	if (sh->funcs->set_enabled == NULL) {
		ERR(sh,
		    "No set_enabled function defined for this connection type.");
		return -1;
	} else if (!sh->is_connected) {
		ERR(sh, "Not connected.");
		return -1;
	} else if (!sh->is_in_transaction) {
		if (semanage_begin_transaction(sh) < 0) {
			return -1;
		}
	}

	sh->modules_modified = 1;
	return sh->funcs->set_enabled(sh, modkey, enabled);
}


/* This function exists only for ABI compatibility. It has been deprecated and
 * should not be used. Instead, use semanage_module_set_enabled() */
int semanage_module_enable(semanage_handle_t *sh, char *module_name)
{
	int rc = -1;
	semanage_module_key_t *modkey = NULL;

	rc = semanage_module_key_create(sh, &modkey);
	if (rc != 0)
		goto exit;

	rc = semanage_module_key_set_name(sh, modkey, module_name);
	if (rc != 0)
		goto exit;

	rc = semanage_module_set_enabled(sh, modkey, 1);
	if (rc != 0)
		goto exit;

	rc = 0;

exit:
	semanage_module_key_destroy(sh, modkey);
	free(modkey);

	return rc;
}

/* This function exists only for ABI compatibility. It has been deprecated and
 * should not be used. Instead, use semanage_module_set_enabled() */
int semanage_module_disable(semanage_handle_t *sh, char *module_name)
{
	int rc = -1;
	semanage_module_key_t *modkey = NULL;

	rc = semanage_module_key_create(sh, &modkey);
	if (rc != 0)
		goto exit;

	rc = semanage_module_key_set_name(sh, modkey, module_name);
	if (rc != 0)
		goto exit;

	rc = semanage_module_set_enabled(sh, modkey, 0);
	if (rc != 0)
		goto exit;

	rc = 0;

exit:
	semanage_module_key_destroy(sh, modkey);
	free(modkey);

	return rc;
}

/* Converts a string to a priority
 *
 * returns -1 if str is not a valid priority.
 * returns 0 and sets priority if str is a valid priority
 */
int semanage_string_to_priority(const char *str, uint16_t *priority)
{
	unsigned long val;
	char *endptr = NULL;
	int status = -1;

	if (str == NULL || priority == NULL) {
		goto exit;
	}

	errno = 0;

	val = strtoul(str, &endptr, 10);

	if (errno != 0 || endptr == str || *endptr != '\0' || val > UINT16_MAX) {
		goto exit;
	}

	if (semanage_module_validate_priority((uint16_t)val) < 0) {
		goto exit;
	}

	*priority = val;
	status = 0;

exit:
	return status;
}

/* Validates a module info struct.
 *
 * Returns -1 if module is invalid, 0 otherwise.
 */
int semanage_module_info_validate(const semanage_module_info_t *modinfo)
{
	if (semanage_module_validate_priority(modinfo->priority) != 0 ||
	    semanage_module_validate_name(modinfo->name) != 0 ||
	    semanage_module_validate_lang_ext(modinfo->lang_ext) != 0 ||
	    semanage_module_validate_enabled(modinfo->enabled) != 0) {
		return -1;
	}
	return 0;
}

#define PRIORITY_MIN 1
#define PRIORITY_MAX 999

/* Validates priority.
 *
 * returns -1 if priority is not in the valid range, returns 0 otherwise
 */
int semanage_module_validate_priority(uint16_t priority)
{
	if (priority >= PRIORITY_MIN && priority <= PRIORITY_MAX) {
		return 0;
	}

	return -1;
}

/* Validates module name.
 *
 * A module name must match one of the following regular expressions
 * to be considered valid:
 *
 * ^[a-zA-Z](\.?[a-zA-Z0-9_-])*$
 *
 * returns -1 if name is not valid, returns 0 otherwise
 */
int semanage_module_validate_name(const char * name)
{
	int status = 0;

	if (name == NULL) {
		status = -1;
		goto exit;
	}

	if (!isalpha(*name)) {
		status = -1;
		goto exit;
	}

#define ISVALIDCHAR(c) (isalnum(c) || c == '_' || c == '-')

	for (name++; *name; name++) {
		if (ISVALIDCHAR(*name)) {
			continue;
		}
		if (*name == '.' && name++ && ISVALIDCHAR(*name)) {
			continue;
		}
		status = -1;
		goto exit;
	}

#undef ISVALIDCHAR

exit:
	return status;
}

/* Validates module enabled status.
 *
 * Valid enabled values are 1, 0, and -1.
 *
 * returns 0 if enabled is a valid value, returns -1 otherwise.
 */
int semanage_module_validate_enabled(int enabled)
{
	if (enabled == 1 || enabled == 0 || enabled == -1) {
		return 0;
	}

	return -1;
}

/* Validate extension.
 *
 * An extension must match the following regular expression to be
 * considered valid:
 *
 * ^[a-zA-Z0-9][a-zA-Z0-9_-]*$
 *
 * returns 0 if ext is a valid value, returns -1 otherwise.
 */
int semanage_module_validate_lang_ext(const char *ext)
{
	int status = 0;

	if (ext == NULL) {
		status = -1;
		goto exit;
	}

	if (!isalnum(*ext)) {
		status = -1;
		goto exit;
	}

#define ISVALIDCHAR(c) (isalnum(c) || c == '_' || c == '-')

	for (ext++; *ext; ext++) {
		if (ISVALIDCHAR(*ext)) {
			continue;
		}
		status = -1;
		goto exit;
	}

#undef ISVALIDCHAR

exit:
	return status;
}

int semanage_module_get_module_info(semanage_handle_t *sh,
				    const semanage_module_key_t *modkey,
				    semanage_module_info_t **modinfo)
{
	assert(sh);
	assert(modkey);
	assert(modinfo);

	if (sh->funcs->get_module_info == NULL) {
		ERR(sh,
		    "No get module info function defined for this connection type.");
		return -1;
	} else if (!sh->is_connected) {
		ERR(sh, "Not connected.");
		return -1;
	}

	return sh->funcs->get_module_info(sh, modkey, modinfo);
}

int semanage_module_list_all(semanage_handle_t *sh,
			     semanage_module_info_t **modinfos,
			     int *modinfos_len)
{
	assert(sh);
	assert(modinfos);
	assert(modinfos_len);

	if (sh->funcs->list_all == NULL) {
		ERR(sh,
		    "No list all function defined for this connection type.");
		return -1;
	} else if (!sh->is_connected) {
		ERR(sh, "Not connected.");
		return -1;
	}

	return sh->funcs->list_all(sh, modinfos, modinfos_len);
}

int semanage_module_install_info(semanage_handle_t *sh,
				 const semanage_module_info_t *modinfo,
				 char *data,
				 size_t data_len)
{
	if (sh->funcs->install_info == NULL) {
		ERR(sh,
		    "No install info function defined for this connection type.");
		return -1;
	} else if (!sh->is_connected) {
		ERR(sh, "Not connected.");
		return -1;
	} else if (!sh->is_in_transaction) {
		if (semanage_begin_transaction(sh) < 0) {
			return -1;
		}
	}
	sh->modules_modified = 1;
	return sh->funcs->install_info(sh, modinfo, data, data_len);
}

int semanage_module_remove_key(semanage_handle_t *sh,
			       const semanage_module_key_t *modkey)
{
	if (sh->funcs->remove_key == NULL) {
		ERR(sh,
		    "No remove key function defined for this connection type.");
		return -1;
	} else if (!sh->is_connected) {
		ERR(sh, "Not connected.");
		return -1;
	} else if (!sh->is_in_transaction) {
		if (semanage_begin_transaction(sh) < 0) {
			return -1;
		}
	}
	sh->modules_modified = 1;
	return sh->funcs->remove_key(sh, modkey);
}

