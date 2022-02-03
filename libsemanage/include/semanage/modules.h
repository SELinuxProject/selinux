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
#include <stdint.h>
#include <semanage/handle.h>
#include <sys/types.h>

typedef struct semanage_module_key semanage_module_key_t;

/* High level module management functions. These are all part of
 * a transaction  
 */

extern int semanage_module_install(semanage_handle_t *,
				   char *module_data, size_t data_len, const char *name, const char *ext_lang);
extern int semanage_module_install_file(semanage_handle_t *,
					const char *module_name);
extern int semanage_module_remove(semanage_handle_t *, char *module_name);

/* semanage_module_info is for getting information on installed
   modules, only name at this time */
typedef struct semanage_module_info semanage_module_info_t;

/* Look up a module using @modkey. The module's raw data is returned as a
 * @mapped_data blob and size of the mapped_data is returned as @data_len.
 * @modinfo contains additional information which can be used by the caller such
 * as the high level language extension of @mapped_data.
 *
 * On success, the caller is responsible for unmapping @mapped_data with munmap(),
 * destroying @modinfo with semanage_module_info_destroy(), and freeing @modinfo.
 *
 * Returns 0 on success and -1 on error.
 */
extern int semanage_module_extract(semanage_handle_t *sh,
				  semanage_module_key_t *modkey,
				  int extract_cil,
				  void **mapped_data,
				  size_t *data_len,
				  semanage_module_info_t **modinfo);
extern int semanage_module_list(semanage_handle_t *,
				semanage_module_info_t **, int *num_modules);
extern void semanage_module_info_datum_destroy(semanage_module_info_t *);
extern semanage_module_info_t *semanage_module_list_nth(semanage_module_info_t * list,
							int n);
extern const char *semanage_module_get_name(semanage_module_info_t *);

/* Module Info */

/* Creates a module info struct.
 *
 * Returns 0 on success and -1 on failure.
 *
 * The @modinfo should be destroyed with semanage_module_info_destroy.
 * The caller should call free() on the struct.
 */
extern int semanage_module_info_create(semanage_handle_t *sh,
				       semanage_module_info_t **modinfo);

/* Frees the members of the module info struct.
 *
 * Returns 0 on success and -1 on failure.
 *
 * The caller should call free() on the struct.
 */
extern int semanage_module_info_destroy(semanage_handle_t *handle,
					semanage_module_info_t *modinfo);

/* Module Info Getters */

/* Get @priority from @modinfo.
 *
 * Returns 0 on success and -1 on error.
 */
extern int semanage_module_info_get_priority(semanage_handle_t *sh,
					     semanage_module_info_t *modinfo,
					     uint16_t *priority);

/* Get @name from @modinfo. Caller should not free @name.
 *
 * Returns 0 on success and -1 on error.
 */
extern int semanage_module_info_get_name(semanage_handle_t *sh,
					 semanage_module_info_t *modinfo,
					 const char **name);

/* Get @lang_ext from @modinfo. Caller should not free @lang_ext.
 *
 * Returns 0 on success and -1 on error.
 */
extern int semanage_module_info_get_lang_ext(semanage_handle_t *sh,
					     semanage_module_info_t *modinfo,
					     const char **lang_ext);

/* Get @enabled from @modinfo.
 *
 * Returns 0 on success and -1 on error.
 */
extern int semanage_module_info_get_enabled(semanage_handle_t *sh,
					    semanage_module_info_t *modinfo,
					    int *enabled);

/* Module Info Setters */

/* Set @priority in @modinfo.
 *
 * Returns 0 on success and -1 on error.
 */
extern int semanage_module_info_set_priority(semanage_handle_t *sh,
					     semanage_module_info_t *modinfo,
					     uint16_t priority);

/* Set @name in @modinfo.
 *
 * Returns 0 on success and -1 on error.
 */
extern int semanage_module_info_set_name(semanage_handle_t *sh,
					 semanage_module_info_t *modinfo,
					 const char *name);

/* Set @lang_ext in @modinfo.
 *
 * Returns 0 on success and -1 on error.
 */
extern int semanage_module_info_set_lang_ext(semanage_handle_t *sh,
					     semanage_module_info_t *modinfo,
					     const char *lang_ext);

/* Set @enabled in @modinfo.
 *
 * Returns 0 on success and -1 on error.
 */
extern int semanage_module_info_set_enabled(semanage_handle_t *sh,
					    semanage_module_info_t *modinfo,
					    int enabled);

/* Module Key */

/* Creates a module key struct.
 *
 * Return 0 on success, and -1 on error.
 *
 * The @modkey should be destroyed with semanage_module_key_destroy.
 * The caller should call free() on the struct.
 */
extern int semanage_module_key_create(semanage_handle_t *sh,
				      semanage_module_key_t **modkey);

/* Frees members of the @modkey, but not the struct. The caller should
 * call free() on struct.
 *
 * Returns 0 on success, and -1 on error.
 */
extern int semanage_module_key_destroy(semanage_handle_t *sh,
				       semanage_module_key_t *modkey);

/* Module Key Getters */

/* Get @name from @modkey. Caller should not free @name.
 *
 * Returns 0 on success and -1 on error.
 */
extern int semanage_module_key_get_name(semanage_handle_t *sh,
					semanage_module_key_t *modkey,
					const char **name);

/* Get @name from @modkey.
 *
 * Returns 0 on success and -1 on error.
 */
extern int semanage_module_key_get_priority(semanage_handle_t *sh,
					    semanage_module_key_t *modkey,
					    uint16_t *priority);

/* Module Key Setters */

/* Set @name in @modkey.
 *
 * Returns 0 on success and -1 on error.
 */
extern int semanage_module_key_set_name(semanage_handle_t *sh,
					semanage_module_key_t *modkey,
					const char *name);

/* Set @priority in @modkey.
 *
 * Returns 0 on success and -1 on error.
 */
extern int semanage_module_key_set_priority(semanage_handle_t *sh,
					    semanage_module_key_t *modkey,
					    uint16_t priority);

/* Set module @enabled status from @modkey. Modules are enabled on a per
 * module name basis (across all priorities). @modkey only needs to have
 * name set (priority is ignored).
 *
 * Returns 0 on success and -1 on error.
 */
extern int semanage_module_set_enabled(semanage_handle_t *sh,
				       const semanage_module_key_t *modkey,
				       int enabled);

/* Lookup @modinfo by @modkey. Caller should use
 * semanage_module_info_destroy and free on @modinfo.
 * 
 * Returns 0 on success and -1 on error.
 */
extern int semanage_module_get_module_info(semanage_handle_t *sh,
					   const semanage_module_key_t *modkey,
					   semanage_module_info_t **modinfo);

/* Create a list of all modules in @modinfos of length @modinfos_len.
 * The list will be sorted from high priority to low and alphabetically
 * by module name within a priority.
 *
 * Caller should use semanage_module_info_destroy on each modinfo in
 * @modinfos and free on @modinfos.
 *
 * Returns 0 on success and -1 on error.
 */
extern int semanage_module_list_all(semanage_handle_t *sh,
				    semanage_module_info_t **modinfos,
				    int *modinfos_len);

/* Install the module indicated by @modinfo with input data from 
 * @module_data with length @data_len.
 *
 * @modinfo must have all values filled in.
 * @module_data may be bzip compressed.
 *
 * Returns:
 *	 0	success
 *	-1	failure, out of memory
 *	-2	failure, invalid @modinfo
 *	-3	failure, error writing file
 */
extern int semanage_module_install_info(semanage_handle_t *sh,
					const semanage_module_info_t *modinfo,
					char *data,
					size_t data_len);

/* Remove the module indicated by @modkey.
 * @modkey must have key values filled in.
 *
 * Returns:
 * 	 0	success
 *	-1	failure, out of memory
 *	-2	failure, @module not found or couldn't be removed
 */
extern int semanage_module_remove_key(semanage_handle_t *sh,
				      const semanage_module_key_t *modkey);

/* Module Enabled */

/* Get module @enabled status from @modkey. Modules are enabled on a per
 * module name basis (across all priorities). @modkey only needs to have
 * name set (priority is ignored).
 *
 * Returns 0 on success and -1 on error.
 */
extern int semanage_module_get_enabled(semanage_handle_t *sh,
				       const semanage_module_key_t *modkey,
				       int *enabled);

/* Compute checksum for @modkey module contents.
 *
 * If @checksum is NULL, the function will just return the length of the
 * checksum string in @checksum_len (checksum strings are guaranteed to
 * have a fixed length for a given libsemanage binary). @modkey and @cil
 * are ignored in this case and should be set to NULL and 0 (respectively).
 *
 * If @checksum is non-NULL, on success, @checksum will point to a buffer
 * containing the checksum string and @checksum_len will point to the
 * length of the string (without the null terminator). The semantics of
 * @cil are the same as for @extract_cil in semanage_module_extract().
 *
 * The caller is responsible to free the buffer returned in @checksum (using
 * free(3)).
 *
 * Callers may assume that if the checksum strings for two modules match,
 * the module content is the same (collisions are theoretically possible,
 * yet extremely unlikely).
 *
 * Returns 0 on success and -1 on error.
 */
extern int semanage_module_compute_checksum(semanage_handle_t *sh,
					    semanage_module_key_t *modkey,
					    int cil, char **checksum,
					    size_t *checksum_len);

#endif
