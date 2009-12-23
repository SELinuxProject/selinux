/* Author: Mark Goldman	  <mgoldman@tresys.com>
 * 	   Paul Rosenfeld <prosenfeld@tresys.com>
 * 	   Todd C. Miller <tmiller@tresys.com>
 *
 * Copyright (C) 2007 Tresys Technology, LLC
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

#include <semanage/handle.h>
#include <semanage/seusers_policy.h>
#include <semanage/users_policy.h>
#include <semanage/user_record.h>
#include <semanage/fcontext_record.h>
#include <semanage/fcontexts_policy.h>
#include <sepol/context.h>
#include <sepol/context_record.h>
#include "semanage_store.h"
#include "seuser_internal.h"
#include "debug.h"

#include "utilities.h"
#include "genhomedircon.h"
#include <ustr.h>

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>
#include <errno.h>
#include <unistd.h>
#include <regex.h>

/* paths used in get_home_dirs() */
#define PATH_ETC_USERADD "/etc/default/useradd"
#define PATH_ETC_LIBUSER "/etc/libuser.conf"
#define PATH_DEFAULT_HOME "/home"
#define PATH_EXPORT_HOME "/export/home"
#define PATH_ETC_LOGIN_DEFS "/etc/login.defs"

/* other paths */
#define PATH_SHELLS_FILE "/etc/shells"
#define PATH_NOLOGIN_SHELL "/sbin/nologin"

/* comments written to context file */
#define COMMENT_FILE_CONTEXT_HEADER "#\n#\n# " \
			"User-specific file contexts, generated via libsemanage\n" \
			"# use semanage command to manage system users to change" \
			" the file_context\n#\n#\n"

#define COMMENT_USER_HOME_CONTEXT "\n\n#\n# Home Context for user %s" \
			"\n#\n\n"

/* placeholders used in the template file
   which are searched for and replaced */
#define TEMPLATE_HOME_ROOT "HOME_ROOT"
#define TEMPLATE_HOME_DIR "HOME_DIR"
#define TEMPLATE_USER "USER"
#define TEMPLATE_ROLE "ROLE"
#define TEMPLATE_SEUSER "system_u"
#define TEMPLATE_LEVEL "s0"

#define FALLBACK_USER "user_u"
#define FALLBACK_USER_PREFIX "user"
#define FALLBACK_USER_LEVEL "s0"
#define DEFAULT_LOGIN "__default__"

typedef struct {
	const char *fcfilepath;
	int usepasswd;
	const char *homedir_template_path;
	char *fallback_user;
	char *fallback_user_prefix;
	char *fallback_user_level;
	semanage_handle_t *h_semanage;
	sepol_policydb_t *policydb;
} genhomedircon_settings_t;

typedef struct user_entry {
	char *name;
	char *sename;
	char *prefix;
	char *home;
	char *level;
	struct user_entry *next;
} genhomedircon_user_entry_t;

typedef struct {
	const char *search_for;
	const char *replace_with;
} replacement_pair_t;

typedef struct {
	const char *dir;
	int matched;
} fc_match_handle_t;

typedef struct IgnoreDir {
	struct IgnoreDir *next;
	char *dir;
} ignoredir_t;

ignoredir_t *ignore_head = NULL;

static void ignore_free(void) {
	ignoredir_t *next;

	while (ignore_head) {
		next = ignore_head->next;
		free(ignore_head->dir);
		free(ignore_head);
		ignore_head = next;
	}
}

static int ignore_setup(char *ignoredirs) {
	char *tok;
	ignoredir_t *ptr = NULL; 

	tok = strtok(ignoredirs, ";");
	while(tok) {
		ptr = calloc(sizeof(ignoredir_t),1);
		if (!ptr)
			goto err;
		ptr->dir = strdup(tok);
		if (!ptr->dir)
			goto err;

		ptr->next = ignore_head;
		ignore_head = ptr;

		tok = strtok(NULL, ";");
	}

	return 0;
err:
	free(ptr);
	ignore_free();
	return -1;
}

static int ignore(const char *homedir) {
	ignoredir_t *ptr = ignore_head;
	while (ptr) {
		if (strcmp(ptr->dir, homedir) == 0) {
			return 1;
		}
		ptr = ptr->next;
	}
	return 0;
}

static semanage_list_t *default_shell_list(void)
{
	semanage_list_t *list = NULL;

	if (semanage_list_push(&list, "/bin/csh")
	    || semanage_list_push(&list, "/bin/tcsh")
	    || semanage_list_push(&list, "/bin/ksh")
	    || semanage_list_push(&list, "/bin/bsh")
	    || semanage_list_push(&list, "/bin/ash")
	    || semanage_list_push(&list, "/usr/bin/ksh")
	    || semanage_list_push(&list, "/usr/bin/pdksh")
	    || semanage_list_push(&list, "/bin/zsh")
	    || semanage_list_push(&list, "/bin/sh")
	    || semanage_list_push(&list, "/bin/bash"))
		goto fail;

	return list;

      fail:
	semanage_list_destroy(&list);
	return NULL;
}

static semanage_list_t *get_shell_list(void)
{
	FILE *shells;
	char *temp = NULL;
	semanage_list_t *list = NULL;
	size_t buff_len = 0;
	ssize_t len;

	shells = fopen(PATH_SHELLS_FILE, "r");
	if (!shells)
		return default_shell_list();
	while ((len = getline(&temp, &buff_len, shells)) > 0) {
		if (temp[len-1] == '\n') temp[len-1] = 0;
		if (strcmp(temp, PATH_NOLOGIN_SHELL)) {
			if (semanage_list_push(&list, temp)) {
				free(temp);
				semanage_list_destroy(&list);
				return default_shell_list();
			}
		}
	}
	free(temp);

	return list;
}

/* Helper function called via semanage_fcontext_iterate() */
static int fcontext_matches(const semanage_fcontext_t *fcontext, void *varg)
{
	const char *oexpr = semanage_fcontext_get_expr(fcontext);
	fc_match_handle_t *handp = varg;
	struct Ustr *expr;
	regex_t re;
	int type, retval = -1;

	/* Only match ALL or DIR */
	type = semanage_fcontext_get_type(fcontext);
	if (type != SEMANAGE_FCONTEXT_ALL && type != SEMANAGE_FCONTEXT_ALL)
		return 0;

	/* Convert oexpr into a Ustr and anchor it at the beginning */
	expr = ustr_dup_cstr("^");
	if (expr == USTR_NULL)
		goto done;
	if (!ustr_add_cstr(&expr, oexpr))
		goto done;

	/* Strip off trailing ".+" or ".*" */
	if (ustr_cmp_suffix_cstr_eq(expr, ".+") ||
	    ustr_cmp_suffix_cstr_eq(expr, ".*")) {
		if (!ustr_del(&expr, 2))
			goto done;
	}

	/* Strip off trailing "(/.*)?" */
	if (ustr_cmp_suffix_cstr_eq(expr, "(/.*)?")) {
		if (!ustr_del(&expr, 6))
			goto done;
	}

	if (ustr_cmp_suffix_cstr_eq(expr, "/")) {
		if (!ustr_del(&expr, 1))
			goto done;
	}

	/* Append pattern to eat up trailing slashes */
	if (!ustr_add_cstr(&expr, "/*$"))
		goto done;

	/* Check dir against expr */
	if (regcomp(&re, ustr_cstr(expr), REG_EXTENDED) != 0)
		goto done;
	if (regexec(&re, handp->dir, 0, NULL, 0) == 0)
		handp->matched = 1;
	regfree(&re);

	retval = 0;

done:
	ustr_free(expr);

	return retval;
}

static semanage_list_t *get_home_dirs(genhomedircon_settings_t * s)
{
	semanage_list_t *homedir_list = NULL;
	semanage_list_t *shells = NULL;
	fc_match_handle_t hand;
	char *rbuf = NULL;
	char *path = NULL;
	long rbuflen;
	uid_t temp, minuid = 500, maxuid = 60000;
	int minuid_set = 0;
	struct passwd pwstorage, *pwbuf;
	struct stat buf;
	int retval;

	path = semanage_findval(PATH_ETC_USERADD, "HOME", "=");
	if (path && *path) {
		if (semanage_list_push(&homedir_list, path))
			goto fail;
	}
	free(path);

	path = semanage_findval(PATH_ETC_LIBUSER, "LU_HOMEDIRECTORY", "=");
	if (path && *path) {
		if (semanage_list_push(&homedir_list, path))
			goto fail;
	}
	free(path);
	path = NULL;

	if (!homedir_list) {
		if (semanage_list_push(&homedir_list, PATH_DEFAULT_HOME)) {
			goto fail;
		}
	}

	if (!stat(PATH_EXPORT_HOME, &buf)) {
		if (S_ISDIR(buf.st_mode)) {
			if (semanage_list_push(&homedir_list, PATH_EXPORT_HOME)) {
				goto fail;
			}
		}
	}

	if (!(s->usepasswd))
		return homedir_list;

	shells = get_shell_list();
	assert(shells);

	path = semanage_findval(PATH_ETC_LOGIN_DEFS, "UID_MIN", NULL);
	if (path && *path) {
		temp = atoi(path);
		minuid = temp;
		minuid_set = 1;
	}
	free(path);
	path = NULL;

	path = semanage_findval(PATH_ETC_LOGIN_DEFS, "UID_MAX", NULL);
	if (path && *path) {
		temp = atoi(path);
		maxuid = temp;
	}
	free(path);
	path = NULL;

	path = semanage_findval(PATH_ETC_LIBUSER, "LU_UIDNUMBER", "=");
	if (path && *path) {
		temp = atoi(path);
		if (!minuid_set || temp < minuid) {
			minuid = temp;
			minuid_set = 1;
		}
	}
	free(path);
	path = NULL;

	rbuflen = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (rbuflen <= 0)
		goto fail;
	rbuf = malloc(rbuflen);
	if (rbuf == NULL)
		goto fail;
	setpwent();
	while ((retval = getpwent_r(&pwstorage, rbuf, rbuflen, &pwbuf)) == 0) {
		if (pwbuf->pw_uid < minuid || pwbuf->pw_uid > maxuid)
			continue;
		if (!semanage_list_find(shells, pwbuf->pw_shell))
			continue;
		int len = strlen(pwbuf->pw_dir) -1;
		for(; len > 0 && pwbuf->pw_dir[len] == '/'; len--) {
			pwbuf->pw_dir[len] = '\0';
		}
		if (strcmp(pwbuf->pw_dir, "/") == 0)
			continue;
		if (ignore(pwbuf->pw_dir))
			continue;
		if (semanage_str_count(pwbuf->pw_dir, '/') <= 1)
			continue;
		if (!(path = strdup(pwbuf->pw_dir))) {
			break;
		}

		semanage_rtrim(path, '/');

		if (!semanage_list_find(homedir_list, path)) {
			/*
			 * Now check for an existing file context that matches
			 * so we don't label a non-homedir as a homedir.
			 */
			hand.dir = path;
			hand.matched = 0;
			if (semanage_fcontext_iterate(s->h_semanage,
			    fcontext_matches, &hand) == STATUS_ERR)
				goto fail;

			/* NOTE: old genhomedircon printed a warning on match */
			if (hand.matched) {
				WARN(s->h_semanage, "%s homedir %s or its parent directory conflicts with a file context already specified in the policy.  This usually indicates an incorrectly defined system account.  If it is a system account please make sure its uid is less than %u or greater than %u or its login shell is /sbin/nologin.", pwbuf->pw_name, pwbuf->pw_dir, minuid, maxuid);
			} else {
				if (semanage_list_push(&homedir_list, path))
					goto fail;
			}
		}
		free(path);
		path = NULL;
	}

	if (retval && retval != ENOENT) {
		WARN(s->h_semanage, "Error while fetching users.  "
		     "Returning list so far.");
	}

	if (semanage_list_sort(&homedir_list))
		goto fail;

	endpwent();
	free(rbuf);
	semanage_list_destroy(&shells);

	return homedir_list;

      fail:
	endpwent();
	free(rbuf);
	free(path);
	semanage_list_destroy(&homedir_list);
	semanage_list_destroy(&shells);
	return NULL;
}

/**
 * @param	out	the FILE to put all the output in.
 * @return	0 on success
 */
static int write_file_context_header(FILE * out)
{
	if (fprintf(out, COMMENT_FILE_CONTEXT_HEADER) < 0) {
		return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}

/* Predicates for use with semanage_slurp_file_filter() the homedir_template
 * file currently contains lines that serve as the template for a user's
 * homedir.
 *
 * It also contains lines that are the template for the parent of a
 * user's home directory.
 *
 * Currently, the only lines that apply to the the root of a user's home
 * directory are all prefixed with the string "HOME_ROOT".  All other
 * lines apply to a user's home directory.  If this changes the
 * following predicates need to change to reflect that.
 */
static int HOME_ROOT_PRED(const char *string)
{
	return semanage_is_prefix(string, TEMPLATE_HOME_ROOT);
}

static int HOME_DIR_PRED(const char *string)
{
	return semanage_is_prefix(string, TEMPLATE_HOME_DIR);
}

static int USER_CONTEXT_PRED(const char *string)
{
	return (int)(strstr(string, TEMPLATE_USER) != NULL);
}

/* make_tempate
 * @param	s	  the settings holding the paths to various files
 * @param	pred	function pointer to function to use as filter for slurp
 * 					file filter
 * @return   a list of lines from the template file with inappropriate
 *	    lines filtered out.
 */
static semanage_list_t *make_template(genhomedircon_settings_t * s,
				      int (*pred) (const char *))
{
	FILE *template_file = NULL;
	semanage_list_t *template_data = NULL;

	template_file = fopen(s->homedir_template_path, "r");
	if (!template_file)
		return NULL;
	template_data = semanage_slurp_file_filter(template_file, pred);
	fclose(template_file);

	return template_data;
}

static Ustr *replace_all(const char *str, const replacement_pair_t * repl)
{
	Ustr *retval = USTR_NULL;
	int i;

	if (!str || !repl)
		goto done;
	if (!(retval = ustr_dup_cstr(str)))
		goto done;

	for (i = 0; repl[i].search_for; i++) {
		ustr_replace_cstr(&retval, repl[i].search_for,
				  repl[i].replace_with, 0);
	}
	if (ustr_enomem(retval))
		ustr_sc_free(&retval);

      done:
	return retval;
}

static const char * extract_context(Ustr *line)
{
	const char whitespace[] = " \t\n";
	size_t off, len;

	/* check for trailing whitespace */
	off = ustr_spn_chrs_rev(line, 0, whitespace, strlen(whitespace));

	/* find the length of the last field in line */
	len = ustr_cspn_chrs_rev(line, off, whitespace, strlen(whitespace));

	if (len == 0)
		return NULL;
	return ustr_cstr(line) + ustr_len(line) - (len + off);
}

static int check_line(genhomedircon_settings_t * s, Ustr *line)
{
	sepol_context_t *ctx_record = NULL;
	const char *ctx_str;
	int result;

	ctx_str = extract_context(line);
	if (!ctx_str)
		return STATUS_ERR;

	result = sepol_context_from_string(s->h_semanage->sepolh,
					   ctx_str, &ctx_record);
	if (result == STATUS_SUCCESS && ctx_record != NULL) {
		sepol_msg_set_callback(s->h_semanage->sepolh, NULL, NULL);
		result = sepol_context_check(s->h_semanage->sepolh,
					     s->policydb, ctx_record);
		sepol_msg_set_callback(s->h_semanage->sepolh,
				       semanage_msg_relay_handler, s->h_semanage);
		sepol_context_free(ctx_record);
	}
	return result;
}

static int write_home_dir_context(genhomedircon_settings_t * s, FILE * out,
				  semanage_list_t * tpl, const char *user,
				  const char *seuser, const char *home,
				  const char *role_prefix, const char *level)
{
	replacement_pair_t repl[] = {
		{.search_for = TEMPLATE_SEUSER,.replace_with = seuser},
		{.search_for = TEMPLATE_HOME_DIR,.replace_with = home},
		{.search_for = TEMPLATE_ROLE,.replace_with = role_prefix},
		{.search_for = TEMPLATE_LEVEL,.replace_with = level},
		{NULL, NULL}
	};
	Ustr *line = USTR_NULL;

	if (fprintf(out, COMMENT_USER_HOME_CONTEXT, user) < 0)
		return STATUS_ERR;

	for (; tpl; tpl = tpl->next) {
		line = replace_all(tpl->data, repl);
		if (!line)
			goto fail;
		if (check_line(s, line) == STATUS_SUCCESS) {
			if (!ustr_io_putfileline(&line, out))
				goto fail;
		}
		ustr_sc_free(&line);
	}
	return STATUS_SUCCESS;

      fail:
	ustr_sc_free(&line);
	return STATUS_ERR;
}

static int write_home_root_context(genhomedircon_settings_t * s, FILE * out,
				   semanage_list_t * tpl, char *homedir)
{
	replacement_pair_t repl[] = {
		{.search_for = TEMPLATE_HOME_ROOT,.replace_with = homedir},
		{NULL, NULL}
	};
	Ustr *line = USTR_NULL;

	for (; tpl; tpl = tpl->next) {
		line = replace_all(tpl->data, repl);
		if (!line)
			goto fail;
		if (check_line(s, line) == STATUS_SUCCESS) {
			if (!ustr_io_putfileline(&line, out))
				goto fail;
		}
		ustr_sc_free(&line);
	}
	return STATUS_SUCCESS;

      fail:
	ustr_sc_free(&line);
	return STATUS_ERR;
}

static int write_user_context(genhomedircon_settings_t * s, FILE * out,
			      semanage_list_t * tpl, const char *user,
			      const char *seuser, const char *role_prefix)
{
	replacement_pair_t repl[] = {
		{.search_for = TEMPLATE_USER,.replace_with = user},
		{.search_for = TEMPLATE_ROLE,.replace_with = role_prefix},
		{.search_for = TEMPLATE_SEUSER,.replace_with = seuser},
		{NULL, NULL}
	};
	Ustr *line = USTR_NULL;

	for (; tpl; tpl = tpl->next) {
		line = replace_all(tpl->data, repl);
		if (!line)
			goto fail;
		if (check_line(s, line) == STATUS_SUCCESS) {
			if (!ustr_io_putfileline(&line, out))
				goto fail;
		}
		ustr_sc_free(&line);
	}
	return STATUS_SUCCESS;

      fail:
	ustr_sc_free(&line);
	return STATUS_ERR;
}

static int user_sort_func(semanage_user_t ** arg1, semanage_user_t ** arg2)
{
	return strcmp(semanage_user_get_name(*arg1),
		      semanage_user_get_name(*arg2));
}

static int name_user_cmp(char *key, semanage_user_t ** val)
{
	return strcmp(key, semanage_user_get_name(*val));
}

static int push_user_entry(genhomedircon_user_entry_t ** list, const char *n,
			   const char *sen, const char *pre, const char *h,
			   const char *l)
{
	genhomedircon_user_entry_t *temp = NULL;
	char *name = NULL;
	char *sename = NULL;
	char *prefix = NULL;
	char *home = NULL;
	char *level = NULL;

	temp = malloc(sizeof(genhomedircon_user_entry_t));
	if (!temp)
		goto cleanup;
	name = strdup(n);
	if (!name)
		goto cleanup;
	sename = strdup(sen);
	if (!sename)
		goto cleanup;
	prefix = strdup(pre);
	if (!prefix)
		goto cleanup;
	home = strdup(h);
	if (!home)
		goto cleanup;
	level = strdup(l);
	if (!level)
		goto cleanup;

	temp->name = name;
	temp->sename = sename;
	temp->prefix = prefix;
	temp->home = home;
	temp->level = level;
	temp->next = (*list);
	(*list) = temp;

	return STATUS_SUCCESS;

      cleanup:
	free(name);
	free(sename);
	free(prefix);
	free(home);
	free(level);
	free(temp);
	return STATUS_ERR;
}

static void pop_user_entry(genhomedircon_user_entry_t ** list)
{
	genhomedircon_user_entry_t *temp;

	if (!list || !(*list))
		return;

	temp = *list;
	*list = temp->next;
	free(temp->name);
	free(temp->sename);
	free(temp->prefix);
	free(temp->home);
	free(temp->level);
	free(temp);
}

static int set_fallback_user(genhomedircon_settings_t *s, const char *user,
			     const char *prefix, const char *level)
{
	char *fallback_user = strdup(user);
	char *fallback_user_prefix = strdup(prefix);
	char *fallback_user_level = NULL;
	if (level) 
		fallback_user_level = strdup(level);

	if (fallback_user == NULL || fallback_user_prefix == NULL ||
	    (fallback_user_level == NULL && level != NULL)) {
		free(fallback_user);
		free(fallback_user_prefix);
		free(fallback_user_level);
		return STATUS_ERR;
	}

	free(s->fallback_user);
	free(s->fallback_user_prefix);
	free(s->fallback_user_level);
	s->fallback_user = fallback_user;
	s->fallback_user_prefix = fallback_user_prefix;
	s->fallback_user_level = fallback_user_level;
	return STATUS_SUCCESS;
}

static int setup_fallback_user(genhomedircon_settings_t * s)
{
	semanage_seuser_t **seuser_list = NULL;
	unsigned int nseusers = 0;
	semanage_user_key_t *key = NULL;
	semanage_user_t *u = NULL;
	const char *name = NULL;
	const char *seuname = NULL;
	const char *prefix = NULL;
	const char *level = NULL;
	unsigned int i;
	int retval;
	int errors = 0;

	retval = semanage_seuser_list(s->h_semanage, &seuser_list, &nseusers);
	if (retval < 0 || (nseusers < 1)) {
		/* if there are no users, this function can't do any other work */
		return errors;
	}

	for (i = 0; i < nseusers; i++) {
		name = semanage_seuser_get_name(seuser_list[i]);
		if (strcmp(name, DEFAULT_LOGIN) == 0) {
			seuname = semanage_seuser_get_sename(seuser_list[i]);

			/* find the user structure given the name */
			if (semanage_user_key_create(s->h_semanage, seuname,
						     &key) < 0) {
				errors = STATUS_ERR;
				break;
			}
			if (semanage_user_query(s->h_semanage, key, &u) < 0)
			{
				prefix = name;
				level = FALLBACK_USER_LEVEL;
			}
			else
			{
				prefix = semanage_user_get_prefix(u);
				level = semanage_user_get_mlslevel(u);
				if (!level)
					level = FALLBACK_USER_LEVEL;
			}

			if (set_fallback_user(s, seuname, prefix, level) != 0)
				errors = STATUS_ERR;
			semanage_user_key_free(key);
			if (u)
				semanage_user_free(u);
			break;
		}
	}

	for (i = 0; i < nseusers; i++)
		semanage_seuser_free(seuser_list[i]);
	free(seuser_list);

	return errors;
}

static genhomedircon_user_entry_t *get_users(genhomedircon_settings_t * s,
					     int *errors)
{
	genhomedircon_user_entry_t *head = NULL;
	semanage_seuser_t **seuser_list = NULL;
	unsigned int nseusers = 0;
	semanage_user_t **user_list = NULL;
	unsigned int nusers = 0;
	semanage_user_t **u = NULL;
	const char *name = NULL;
	const char *seuname = NULL;
	const char *prefix = NULL;
	const char *level = NULL;
	struct passwd pwstorage, *pwent = NULL;
	unsigned int i;
	long rbuflen;
	char *rbuf = NULL;
	int retval;

	*errors = 0;
	retval = semanage_seuser_list(s->h_semanage, &seuser_list, &nseusers);
	if (retval < 0 || (nseusers < 1)) {
		/* if there are no users, this function can't do any other work */
		return NULL;
	}

	if (semanage_user_list(s->h_semanage, &user_list, &nusers) < 0) {
		nusers = 0;
	}

	qsort(user_list, nusers, sizeof(semanage_user_t *),
	      (int (*)(const void *, const void *))&user_sort_func);

	/* Allocate space for the getpwnam_r buffer */
	rbuflen = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (rbuflen <= 0)
		goto cleanup;
	rbuf = malloc(rbuflen);
	if (rbuf == NULL)
		goto cleanup;

	for (i = 0; i < nseusers; i++) {
		seuname = semanage_seuser_get_sename(seuser_list[i]);
		name = semanage_seuser_get_name(seuser_list[i]);

		if (strcmp(name,"root") && strcmp(seuname, s->fallback_user) == 0)
			continue;

		if (strcmp(name, DEFAULT_LOGIN) == 0)
			continue;

		if (strcmp(name, TEMPLATE_SEUSER) == 0)
			continue;

		/* %groupname syntax */
		if (name[0] == '%')
			continue;

		/* find the user structure given the name */
		u = bsearch(seuname, user_list, nusers, sizeof(semanage_user_t *),
			    (int (*)(const void *, const void *))
			    &name_user_cmp);
		if (u) {
			prefix = semanage_user_get_prefix(*u);
			level = semanage_user_get_mlslevel(*u);
			if (!level)
				level = FALLBACK_USER_LEVEL;
		} else {
			prefix = name;
			level = FALLBACK_USER_LEVEL;
		}

		retval = getpwnam_r(name, &pwstorage, rbuf, rbuflen, &pwent);
		if (retval != 0 || pwent == NULL) {
			if (retval != 0 && retval != ENOENT) {
				*errors = STATUS_ERR;
				goto cleanup;
			}

			WARN(s->h_semanage,
			     "user %s not in password file", name);
			continue;
		}

		int len = strlen(pwent->pw_dir) -1;
		for(; len > 0 && pwent->pw_dir[len] == '/'; len--) {
			pwent->pw_dir[len] = '\0';
		}

		if (strcmp(pwent->pw_dir, "/") == 0) {
			/* don't relabel / genhomdircon checked to see if root
			 * was the user and if so, set his home directory to
			 * /root */
			continue;
		}
		if (ignore(pwent->pw_dir))
			continue;
		if (push_user_entry(&head, name, seuname,
				    prefix, pwent->pw_dir, level) != STATUS_SUCCESS) {
			*errors = STATUS_ERR;
			break;
		}
	}

      cleanup:
	free(rbuf);
	if (*errors) {
		for (; head; pop_user_entry(&head)) {
			/* the pop function takes care of all the cleanup
			   so the loop body is just empty */
		}
	}
	for (i = 0; i < nseusers; i++) {
		semanage_seuser_free(seuser_list[i]);
	}
	free(seuser_list);

	for (i = 0; i < nusers; i++) {
		semanage_user_free(user_list[i]);
	}
	free(user_list);

	return head;
}

static int write_gen_home_dir_context(genhomedircon_settings_t * s, FILE * out,
				      semanage_list_t * user_context_tpl,
				      semanage_list_t * homedir_context_tpl)
{
	genhomedircon_user_entry_t *users;
	int errors = 0;

	users = get_users(s, &errors);
	if (!users && errors) {
		return STATUS_ERR;
	}

	for (; users; pop_user_entry(&users)) {
		if (write_home_dir_context(s, out, homedir_context_tpl,
					   users->name,
					   users->sename, users->home,
					   users->prefix, users->level))
			goto err;
		if (write_user_context(s, out, user_context_tpl, users->name,
				       users->sename, users->prefix))
			goto err;
	}

	return STATUS_SUCCESS;
err:
	for (; users; pop_user_entry(&users)) {
	/* the pop function takes care of all the cleanup
	 * so the loop body is just empty */
	}

	return STATUS_ERR;
}

/**
 * @param	s	settings structure, stores various paths etc. Must never be NULL
 * @param	out	the FILE to put all the output in.
 * @return	0 on success
 */
static int write_context_file(genhomedircon_settings_t * s, FILE * out)
{
	semanage_list_t *homedirs = NULL;
	semanage_list_t *h = NULL;
	semanage_list_t *user_context_tpl = NULL;
	semanage_list_t *homedir_context_tpl = NULL;
	semanage_list_t *homeroot_context_tpl = NULL;
	int retval = STATUS_SUCCESS;

	homedir_context_tpl = make_template(s, &HOME_DIR_PRED);
	homeroot_context_tpl = make_template(s, &HOME_ROOT_PRED);
	user_context_tpl = make_template(s, &USER_CONTEXT_PRED);

	if (!homedir_context_tpl && !homeroot_context_tpl && !user_context_tpl)
		goto done;

	if (write_file_context_header(out) != STATUS_SUCCESS) {
		retval = STATUS_ERR;
		goto done;
	}

	if (setup_fallback_user(s) != 0) {
		retval = STATUS_ERR;
		goto done;
	}

	if (homedir_context_tpl || homeroot_context_tpl) {
		homedirs = get_home_dirs(s);
		if (!homedirs) {
			WARN(s->h_semanage,
			     "no home directories were available, exiting without writing");
			goto done;
		}

		for (h = homedirs; h; h = h->next) {
			Ustr *temp = ustr_dup_cstr(h->data);

			if (!temp || !ustr_add_cstr(&temp, "/[^/]*")) {
				ustr_sc_free(&temp);
				retval = STATUS_ERR;
				goto done;
			}

			if (write_home_dir_context(s, out,
						   homedir_context_tpl,
						   s->fallback_user, s->fallback_user,
						   ustr_cstr(temp),
						   s->fallback_user_prefix, s->fallback_user_level) !=
			    STATUS_SUCCESS) {
				ustr_sc_free(&temp);
				retval = STATUS_ERR;
				goto done;
			}
			if (write_home_root_context(s, out,
						    homeroot_context_tpl,
						    h->data) != STATUS_SUCCESS) {
				ustr_sc_free(&temp);
				retval = STATUS_ERR;
				goto done;
			}

			ustr_sc_free(&temp);
		}
	}
	if (user_context_tpl) {
		if (write_user_context(s, out, user_context_tpl,
				       ".*", s->fallback_user,
				       s->fallback_user_prefix) != STATUS_SUCCESS) {
			retval = STATUS_ERR;
			goto done;
		}

		if (write_gen_home_dir_context(s, out, user_context_tpl,
					       homedir_context_tpl) != STATUS_SUCCESS) {
			retval = STATUS_ERR;
		}
	}

done:
	/* Cleanup */
	semanage_list_destroy(&homedirs);
	semanage_list_destroy(&user_context_tpl);
	semanage_list_destroy(&homedir_context_tpl);
	semanage_list_destroy(&homeroot_context_tpl);

	return retval;
}

int semanage_genhomedircon(semanage_handle_t * sh,
			   sepol_policydb_t * policydb,
			   int usepasswd, 
			   char *ignoredirs)
{
	genhomedircon_settings_t s;
	FILE *out = NULL;
	int retval = 0;

	assert(sh);

	s.homedir_template_path =
	    semanage_path(SEMANAGE_TMP, SEMANAGE_HOMEDIR_TMPL);
	s.fcfilepath = semanage_final_path(SEMANAGE_FINAL_TMP,
					   SEMANAGE_FC_HOMEDIRS);

	s.fallback_user = strdup(FALLBACK_USER);
	s.fallback_user_prefix = strdup(FALLBACK_USER_PREFIX);
	s.fallback_user_level = strdup(FALLBACK_USER_LEVEL);
	if (s.fallback_user == NULL || s.fallback_user_prefix == NULL || s.fallback_user_level == NULL) {
		retval = STATUS_ERR;
		goto done;
	}

	if (ignoredirs) ignore_setup(ignoredirs);

	s.usepasswd = usepasswd;
	s.h_semanage = sh;
	s.policydb = policydb;

	if (!(out = fopen(s.fcfilepath, "w"))) {
		/* couldn't open output file */
		ERR(sh, "Could not open the file_context file for writing");
		retval = STATUS_ERR;
		goto done;
	}

	retval = write_context_file(&s, out);

done:
	if (out != NULL)
		fclose(out);

	free(s.fallback_user);
	free(s.fallback_user_prefix);
	free(s.fallback_user_level);
	ignore_free();

	return retval;
}
