/* Authors: Joshua Brindle  <jbrindle@tresys.com>
 *	    Jason Tang	    <jtang@tresys.com>
 *
 * Copyright (C) 2005 Tresys Technology, LLC
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

#ifndef _SEMANAGE_MODULES_H_
#define _SEMANAGE_MODULES_H_

#include <stddef.h>
#include <semanage/handle.h>

/* High level module management functions. These are all part of
 * a transaction  
 */

int semanage_module_install(semanage_handle_t *,
			    char *module_data, size_t data_len);
int semanage_module_install_file(semanage_handle_t *,
				 const char *module_name);
int semanage_module_upgrade(semanage_handle_t *,
			    char *module_data, size_t data_len);
int semanage_module_upgrade_file(semanage_handle_t *,
				 const char *module_name);
int semanage_module_install_base(semanage_handle_t *,
				 char *module_data, size_t data_len);
int semanage_module_install_base_file(semanage_handle_t *,
				      const char *module_name);
int semanage_module_enable(semanage_handle_t *, char *module_name);
int semanage_module_disable(semanage_handle_t *, char *module_name);
int semanage_module_remove(semanage_handle_t *, char *module_name);

/* semanage_module_info is for getting information on installed
   modules, only name and version, and enabled/disabled flag at this time */
typedef struct semanage_module_info semanage_module_info_t;

int semanage_module_list(semanage_handle_t *,
			 semanage_module_info_t **, int *num_modules);
void semanage_module_info_datum_destroy(semanage_module_info_t *);
semanage_module_info_t *semanage_module_list_nth(semanage_module_info_t * list,
						 int n);
const char *semanage_module_get_name(semanage_module_info_t *);
const char *semanage_module_get_version(semanage_module_info_t *);
int semanage_module_get_enabled(semanage_module_info_t *);

#endif
