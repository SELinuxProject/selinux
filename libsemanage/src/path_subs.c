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

#include "path_subs.h"

#include "debug.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The rules are kept in reverse file order so that a plain scan
 * yields the last matching rule in the file. */

void semanage_path_subs_free(semanage_path_subs_t **rules)
{
	semanage_path_subs_t *next;

	while (*rules) {
		next = (*rules)->next;
		free((*rules)->alias);
		free((*rules)->original);
		free(*rules);
		*rules = next;
	}
}

int semanage_path_subs_load_file(semanage_handle_t *sh, FILE *fp,
				 const char *path, semanage_path_subs_t **rules)
{
	char *line = NULL, *alias, *orig, *ptr;
	size_t buff_len = 0;
	ssize_t len;
	semanage_path_subs_t *rule;

	*rules = NULL;

	while ((len = getline(&line, &buff_len, fp)) > 0) {
		size_t alias_len, plen;
		bool has_wild;

		alias = line;
		while (*alias && isspace((unsigned char)*alias))
			alias++;
		if (*alias == '#')
			continue;
		ptr = alias;
		while (*ptr && !isspace((unsigned char)*ptr))
			ptr++;
		if (*ptr)
			*ptr++ = '\0';
		if (!*alias)
			continue;

		orig = ptr;
		while (*orig && isspace((unsigned char)*orig))
			orig++;
		ptr = orig;
		while (*ptr && !isspace((unsigned char)*ptr))
			ptr++;
		*ptr = '\0';
		if (!*orig)
			continue;

		/* A '*' in the alias is a single-component wildcard and
		 * must span a whole path component; plen is the length
		 * of the literal prefix before the first '*'. */
		alias_len = strlen(alias);
		plen = alias_len;
		has_wild = false;
		for (size_t j = 0; j < alias_len; j++) {
			if (alias[j] != '*')
				continue;
			if ((j > 0 && alias[j - 1] != '/') ||
			    (alias[j + 1] != '/' && alias[j + 1] != '\0')) {
				ERR(sh,
				    "%s: '*' in substitution source '%s' is not a whole path component",
				    path, alias);
				goto err;
			}
			if (!has_wild)
				plen = j;
			has_wild = true;
		}

		rule = calloc(1, sizeof(*rule));
		if (!rule)
			goto err;
		rule->alias = strdup(alias);
		rule->original = strdup(orig);
		if (!rule->alias || !rule->original) {
			free(rule->alias);
			free(rule->original);
			free(rule);
			goto err;
		}
		rule->alias_len = alias_len;
		rule->plen = plen;
		rule->has_wild = has_wild;
		rule->next = *rules;
		*rules = rule;
	}

	if (ferror(fp)) {
		ERR(sh, "%s: error while reading substitution rules", path);
		goto err;
	}

	free(line);

	return 0;

err:
	free(line);
	semanage_path_subs_free(rules);
	return -1;
}

int semanage_path_subs_load(semanage_handle_t *sh, const char *path,
			    semanage_path_subs_t **rules)
{
	FILE *fp;
	int rc;

	*rules = NULL;

	fp = fopen(path, "re");
	if (!fp)
		return errno == ENOENT ? 0 : -1;

	rc = semanage_path_subs_load_file(sh, fp, path, rules);

	fclose(fp);

	return rc;
}

/* Match "path" against the wildcard part of "rule"; the literal
 * prefix before the first '*' has already been checked by the caller.
 * Sets *matched to the length of the matched source prefix. */
static bool match_wild(const semanage_path_subs_t *rule, const char *path,
		       size_t *matched)
{
	const char *pat = rule->alias + rule->plen;
	const char *in = path + rule->plen;
	bool trailing_wild = false;

	while (*pat) {
		if (pat[0] == '*' && (pat == rule->alias || pat[-1] == '/') &&
		    (pat[1] == '/' || pat[1] == '\0')) {
			/* Consume one non-empty component of the input. */
			if (*in == '/' || *in == '\0')
				return false;
			while (*in && *in != '/')
				in++;
			trailing_wild = (pat[1] == '\0');
			pat++;
		} else if (*pat == *in) {
			trailing_wild = false;
			pat++;
			in++;
		} else
			return false;
	}

	if (trailing_wild) {
		if (*in != '/')
			return false;
	} else if (*in != '/' && *in != '\0')
		return false;

	*matched = (size_t)(in - path);
	return true;
}

int semanage_path_subs_apply(const semanage_path_subs_t *rules,
			     const char *path, char **result)
{
	size_t skip;
	char *out;

	*result = NULL;

	for (; rules; rules = rules->next) {
		if (strncmp(path, rules->alias, rules->plen) != 0)
			continue;

		if (!rules->has_wild) {
			if (path[rules->alias_len] != '/' &&
			    path[rules->alias_len] != '\0')
				continue;
			skip = rules->alias_len;
		} else if (!match_wild(rules, path, &skip))
			continue;

		if (path[skip] == '/' && strcmp(rules->original, "/") == 0)
			/* avoid a double slash when the original is "/" */
			skip++;
		if (asprintf(&out, "%s%s", rules->original, path + skip) < 0)
			return -1;

		*result = out;
		return 0;
	}

	return 0;
}

int semanage_path_subs_canonicalize(const semanage_path_subs_t *local,
				    const semanage_path_subs_t *dist,
				    const char *path, char **result)
{
	char *local_result;
	int rc;

	*result = NULL;

	rc = semanage_path_subs_apply(local, path, &local_result);
	if (rc < 0)
		return -1;

	if (!local_result)
		return semanage_path_subs_apply(dist, path, result);

	rc = semanage_path_subs_apply(dist, local_result, result);
	if (rc < 0 || *result) {
		free(local_result);
		return rc;
	}

	/* no distribution rule applies to the local result */
	*result = local_result;
	return 0;
}
