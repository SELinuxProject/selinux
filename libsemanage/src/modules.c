/* Author: Joshua Brindle <jbrindle@tresys.co
 *	   Jason Tang	  <jtang@tresys.com>
 *
 * Copyright (C) 2004-2005 Tresys Technology, LLC
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
#include "semanage_conf.h"
#include "semanage_store.h"

#include <stdarg.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

#include "handle.h"
#include "modules.h"
#include "debug.h"

int semanage_module_install(semanage_handle_t * sh,
			    char *module_data, size_t data_len)
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
	return sh->funcs->install(sh, module_data, data_len);
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

int semanage_module_upgrade(semanage_handle_t * sh,
			    char *module_data, size_t data_len)
{
	if (sh->funcs->upgrade == NULL) {
		ERR(sh,
		    "No upgrade function defined for this connection type.");
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
	int rc = sh->funcs->upgrade(sh, module_data, data_len);
	if (rc == -5) /* module did not exist */
		rc = sh->funcs->install(sh, module_data, data_len);
	return rc;
	
}

int semanage_module_upgrade_file(semanage_handle_t * sh,
				 const char *module_name) {

	if (sh->funcs->upgrade_file == NULL) {
		ERR(sh,
		    "No upgrade function defined for this connection type.");
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
	int rc = sh->funcs->upgrade_file(sh, module_name);
	if (rc == -5) /* module did not exist */
		rc = sh->funcs->install_file(sh, module_name);
	return rc;
}

int semanage_module_install_base(semanage_handle_t * sh,
				 char *module_data, size_t data_len)
{
	if (sh->funcs->install_base == NULL) {
		ERR(sh,
		    "No install base function defined for this connection type.");
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
	return sh->funcs->install_base(sh, module_data, data_len);
}

int semanage_module_install_base_file(semanage_handle_t * sh,
				 const char *module_name) {

	if (sh->funcs->install_base_file == NULL) {
		ERR(sh,
		    "No install base function defined for this connection type.");
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
	return sh->funcs->install_base_file(sh, module_name);
}

int semanage_module_enable(semanage_handle_t * sh, char *module_name)
{
	if (sh->funcs->enable == NULL) {
		ERR(sh, "No enable function defined for this connection type.");
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
	return sh->funcs->enable(sh, module_name);
}

int semanage_module_disable(semanage_handle_t * sh, char *module_name)
{
	if (sh->funcs->disable == NULL) {
		ERR(sh, "No disable function defined for this connection type.");
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
	return sh->funcs->disable(sh, module_name);
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
		free(modinfo->name);
		free(modinfo->version);
	}
}

hidden_def(semanage_module_info_datum_destroy)

semanage_module_info_t *semanage_module_list_nth(semanage_module_info_t * list,
						 int n)
{
	return list + n;
}

hidden_def(semanage_module_list_nth)

const char *semanage_module_get_name(semanage_module_info_t * modinfo)
{
	return modinfo->name;
}

hidden_def(semanage_module_get_name)

int semanage_module_get_enabled(semanage_module_info_t * modinfo)
{
	return modinfo->enabled;
}

hidden_def(semanage_module_get_enabled)

const char *semanage_module_get_version(semanage_module_info_t * modinfo)
{
	return modinfo->version;
}

hidden_def(semanage_module_get_version)
