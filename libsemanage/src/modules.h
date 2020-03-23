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

#include "semanage/modules.h"

int semanage_module_install_pp(semanage_handle_t * sh,
			    char *module_data, size_t data_len);
int semanage_module_install_hll(semanage_handle_t * sh,
			    char *module_data, size_t data_len, const char *name, const char *ext_lang);
int semanage_module_upgrade(semanage_handle_t * sh,
			    char *module_data, size_t data_len);
int semanage_module_upgrade_file(semanage_handle_t * sh,
				 const char *module_name);
int semanage_module_install_base(semanage_handle_t * sh,
				 char *module_data, size_t data_len);
int semanage_module_install_base_file(semanage_handle_t * sh,
				 const char *module_name);

/* Module Info */
struct semanage_module_info {
	uint16_t priority;	/* key, module priority */
	char *name;		/* key, module name */
	char *lang_ext;		/* module source language extension */
	int enabled;		/* module enabled/disabled status */
};

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
struct semanage_module_key {
	uint16_t priority;	/* module priority */
	char *name;		/* module name */
};

/* Initializes a pre-allocated module key struct.
 *
 * Returns 0 on success, and -1 on error.
 */
int semanage_module_key_init(semanage_handle_t *sh,
			     semanage_module_key_t *modkey);

/* Module Paths */

enum semanage_module_path_type {
	SEMANAGE_MODULE_PATH_PRIORITY,
	SEMANAGE_MODULE_PATH_NAME,
	SEMANAGE_MODULE_PATH_HLL,
	SEMANAGE_MODULE_PATH_CIL,
	SEMANAGE_MODULE_PATH_LANG_EXT,
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
