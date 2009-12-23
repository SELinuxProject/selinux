/* Author: Joshua Brindle <jbrindle@tresys.com>
 *         Jason Tang     <jtang@tresys.com>
 *         Caleb Case     <ccase@tresys.com>
 *
 * Copyright (C) 2005,2009 Tresys Technology, LLC
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

#ifndef _SEMANAGE_INTERNAL_MODULES_H_
#define _SEMANAGE_INTERNAL_MODULES_H_

#include <stdint.h>

#include "module_internal.h"

/* Module Info */
struct semanage_module_info {
	uint16_t priority;	/* key, module priority */
	char *name;		/* key, module name */
	char *version;		/* module version */
	char *lang_ext;		/* module source language extension */
	int enabled;		/* module enabled/disabled status */
};

/* Creates a module info struct.
 *
 * Returns 0 on success and -1 on failure.
 *
 * The @modinfo should be destroyed with semanage_module_info_destroy.
 * The caller should call free() on the struct.
 */
int semanage_module_info_create(semanage_handle_t *sh,
				semanage_module_info_t **modinfo);

/* Frees the members of the module info struct.
 *
 * Returns 0 on success and -1 on failure.
 *
 * The caller should call free() on the struct.
 */
int semanage_module_info_destroy(semanage_handle_t *handle,
				 semanage_module_info_t *modinfo);

/* Initializes a pre-allocated module info struct.
 *
 * Returns 0 on success and -1 on error.
 */
int semanage_module_info_init(semanage_handle_t *sh,
			      semanage_module_info_t *modinfo);

/* Clones module info @source's members into module info @target.
 *
 * Returns 0 on success and -1 on error.
 */
int semanage_module_info_clone(semanage_handle_t *sh,
			       const semanage_module_info_t *source,
			       semanage_module_info_t *target);

/* Module Info Getters */

/* Get @priority from @modinfo.
 *
 * Returns 0 on success and -1 on error.
 */
int semanage_module_info_get_priority(semanage_handle_t *sh,
				      semanage_module_info_t *modinfo,
				      uint16_t *priority);

/* Get @name from @modinfo. Caller should not free @name.
 *
 * Returns 0 on success and -1 on error.
 */
int semanage_module_info_get_name(semanage_handle_t *sh,
				  semanage_module_info_t *modinfo,
				  const char **name);

/* Get @version from @modinfo. Caller should not free @version.
 *
 * Returns 0 on success and -1 on error.
 */
int semanage_module_info_get_version(semanage_handle_t *sh,
				     semanage_module_info_t *modinfo,
				     const char **version);

/* Get @lang_ext from @modinfo. Caller should not free @lang_ext.
 *
 * Returns 0 on success and -1 on error.
 */
int semanage_module_info_get_lang_ext(semanage_handle_t *sh,
				      semanage_module_info_t *modinfo,
				      const char **lang_ext);

/* Get @enabled from @modinfo.
 *
 * Returns 0 on success and -1 on error.
 */
int semanage_module_info_get_enabled(semanage_handle_t *sh,
				     semanage_module_info_t *modinfo,
				     int *enabled);

/* Module Info Setters */

/* Set @priority in @modinfo.
 *
 * Returns 0 on success and -1 on error.
 */
int semanage_module_info_set_priority(semanage_handle_t *sh,
				      semanage_module_info_t *modinfo,
				      uint16_t priority);

/* Set @name in @modinfo.
 *
 * Returns 0 on success and -1 on error.
 */
int semanage_module_info_set_name(semanage_handle_t *sh,
				  semanage_module_info_t *modinfo,
				  const char *name);

/* Set @version in @modinfo.
 *
 * Returns 0 on success and -1 on error.
 */
int semanage_module_info_set_version(semanage_handle_t *sh,
				     semanage_module_info_t *modinfo,
				     const char *version);

/* Set @lang_ext in @modinfo.
 *
 * Returns 0 on success and -1 on error.
 */
int semanage_module_info_set_lang_ext(semanage_handle_t *sh,
				      semanage_module_info_t *modinfo,
				      const char *lang_ext);

/* Set @enabled in @modinfo.
 *
 * Returns 0 on success and -1 on error.
 */
int semanage_module_info_set_enabled(semanage_handle_t *sh,
				     semanage_module_info_t *modinfo,
				     int enabled);

/* Convert a cstring to a priority.
 *
 * Returns 0 on success and -1 on error.
 */
int semanage_string_to_priority(const char *str, uint16_t *priority);

int semanage_module_info_validate(const semanage_module_info_t *modinfo);
int semanage_module_validate_priority(uint16_t priority);
int semanage_module_validate_name(const char *name);
int semanage_module_validate_enabled(int enabled);
int semanage_module_validate_lang_ext(const char *ext);
int semanage_module_validate_version(const char *version);

/* Module Key */
typedef struct semanage_module_key {
	uint16_t priority;	/* module priority */
	char *name;		/* module name */
} semanage_module_key_t;

/* Creates a module key struct.
 *
 * Return 0 on success, and -1 on error.
 *
 * The @modkey should be destroyed with semanage_module_key_destroy.
 * The caller should call free() on the struct.
 */
int semanage_module_key_create(semanage_handle_t *sh,
			       semanage_module_key_t **modkey);

/* Frees members of the @modkey, but not the struct. The caller should
 * call free() on struct.
 *
 * Returns 0 on success, and -1 on error.
 */
int semanage_module_key_destroy(semanage_handle_t *sh,
				semanage_module_key_t *modkey);

/* Initializes a pre-allocated module key struct.
 *
 * Returns 0 on success, and -1 on error.
 */
int semanage_module_key_init(semanage_handle_t *sh,
			     semanage_module_key_t *modkey);

/* Module Key Getters */

/* Get @name from @modkey. Caller should not free @name.
 *
 * Returns 0 on success and -1 on error.
 */
int semanage_module_key_get_name(semanage_handle_t *sh,
				 semanage_module_key_t *modkey,
				 const char **name);

/* Get @name from @modkey.
 *
 * Returns 0 on success and -1 on error.
 */
int semanage_module_key_get_priority(semanage_handle_t *sh,
				     semanage_module_key_t *modkey,
				     uint16_t *priority);

/* Module Key Setters */

/* Set @name in @modkey.
 *
 * Returns 0 on success and -1 on error.
 */
int semanage_module_key_set_name(semanage_handle_t *sh,
				 semanage_module_key_t *modkey,
				 const char *name);

/* Set @priority in @modkey.
 *
 * Returns 0 on success and -1 on error.
 */
int semanage_module_key_set_priority(semanage_handle_t *sh,
				     semanage_module_key_t *modkey,
				     uint16_t priority);

/* Module Paths */

enum semanage_module_path_type {
	SEMANAGE_MODULE_PATH_PRIORITY,
	SEMANAGE_MODULE_PATH_NAME,
	SEMANAGE_MODULE_PATH_HLL,
	SEMANAGE_MODULE_PATH_CIL,
	SEMANAGE_MODULE_PATH_LANG_EXT,
	SEMANAGE_MODULE_PATH_VERSION,
	SEMANAGE_MODULE_PATH_DISABLED,
};

/* Get the module path for the given path @type.
 *
 * Returns 0 on success and -1 on error.
 */
int semanage_module_get_path(semanage_handle_t *sh,
			     const semanage_module_info_t *module,
			     enum semanage_module_path_type type,
			     char *path,
			     size_t len);

#endif
