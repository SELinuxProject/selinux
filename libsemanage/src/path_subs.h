/* Authors: Eugenij Safonov <ja.safonau@protonmail.com>
 *
 * Copyright (C) 2026
 *
 *  This library is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as
 *  published by the Free Software Foundation; either version 2.1 of the
 *  License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 *  02110-1301  USA
 */

#ifndef SEMANAGE_PATH_SUBS_H
#define SEMANAGE_PATH_SUBS_H

#include <semanage/handle.h>

#include <stdbool.h>
#include <stdio.h>

/* Path substitution rules from file_contexts.subs(5): paths under
 * "alias" are looked up by libselinux as paths under "original". */
typedef struct semanage_path_subs {
	char *alias;
	size_t alias_len; /* length of alias */
	size_t plen; /* prefix up to first wildcard, == alias_len if none */
	bool has_wild; /* alias contains one or more '*' whole-component wildcards */
	char *original;
	struct semanage_path_subs *next;
} semanage_path_subs_t;

void semanage_path_subs_free(semanage_path_subs_t **rules);

/* Load path substitution rules from a file_contexts.subs(5)-format
 * file ("alias original" per line, '#' comments).  A missing file is
 * not an error and yields an empty list.  A '*' in the alias is a
 * single-component wildcard and must span a whole path component.
 * Returns 0 on success, -1 on error. */
int semanage_path_subs_load(semanage_handle_t *sh, const char *path,
			    semanage_path_subs_t **rules);

/* Same, from an already opened stream.  The stream is left open. */
int semanage_path_subs_load_file(semanage_handle_t *sh, FILE *fp,
				 const char *path,
				 semanage_path_subs_t **rules);

/* Rewrite "path" according to the rules, matching whole path
 * components, with '*' matching a single component and the last
 * matching rule in the file winning.  On success returns 0 and sets
 * *result to a malloc'd rewritten path, or to NULL when no rule
 * matches.  Returns -1 on error. */
int semanage_path_subs_apply(const semanage_path_subs_t *rules,
			     const char *path, char **result);

/* Canonicalize "path" by applying the local rules first and passing
 * the result through the distribution rules.  On success returns 0
 * and sets *result to a malloc'd canonical path, or to NULL when no
 * rule matches.  Returns -1 on error. */
int semanage_path_subs_canonicalize(const semanage_path_subs_t *local,
				    const semanage_path_subs_t *dist,
				    const char *path, char **result);

#endif
