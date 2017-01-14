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

#include <assert.h>
#include <ctype.h>
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
#include <grp.h>
#include <search.h>

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
/* these are legacy */
#define TEMPLATE_USER "USER"
#define TEMPLATE_ROLE "ROLE"
/* new names */
#define TEMPLATE_USERNAME "%{USERNAME}"
#define TEMPLATE_USERID "%{USERID}"

#define FALLBACK_SENAME "user_u"
#define FALLBACK_PREFIX "user"
#define FALLBACK_LEVEL "s0"
#define FALLBACK_NAME "[^/]+"
#define FALLBACK_UIDGID "[0-9]+"
#define DEFAULT_LOGIN "__default__"

#define CONTEXT_NONE "<<none>>"

typedef struct user_entry {
	char *name;
	char *uid;
	char *gid;
	char *sename;
	char *prefix;
	char *home;
	char *level;
	char *login;
	char *homedir_role;
	struct user_entry *next;
} genhomedircon_user_entry_t;

typedef struct {
	const char *fcfilepath;
	int usepasswd;
	const char *homedir_template_path;
	genhomedircon_user_entry_t *fallback;
	semanage_handle_t *h_semanage;
	sepol_policydb_t *policydb;
} genhomedircon_settings_t;

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

static int prefix_is_homedir_role(const semanage_user_t *user,
				  const char *prefix)
{
	return strcmp(OBJECT_R, prefix) == 0 ||
		semanage_user_has_role(user, prefix);
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
	char *expr = NULL;
	regex_t re;
	int type, retval = -1;
	size_t len;

	/* Only match ALL or DIR */
	type = semanage_fcontext_get_type(fcontext);
	if (type != SEMANAGE_FCONTEXT_ALL && type != SEMANAGE_FCONTEXT_DIR)
		return 0;

	len = strlen(oexpr);
	/* Define a macro to strip a literal string from the end of oexpr */
#define rstrip_oexpr_len(cstr, cstrlen) \
	do { \
		if (len >= (cstrlen) && !strncmp(oexpr + len - (cstrlen), (cstr), (cstrlen))) \
			len -= (cstrlen); \
	} while (0)
#define rstrip_oexpr(cstr) rstrip_oexpr_len(cstr, sizeof(cstr) - 1)

	rstrip_oexpr(".+");
	rstrip_oexpr(".*");
	rstrip_oexpr("(/.*)?");
	rstrip_oexpr("/");

#undef rstrip_oexpr_len
#undef rstrip_oexpr

	/* Anchor oexpr at the beginning and append pattern to eat up trailing slashes */
	if (asprintf(&expr, "^%.*s/*$", (int)len, oexpr) < 0)
		return -1;

	/* Check dir against expr */
	if (regcomp(&re, expr, REG_EXTENDED) != 0)
		goto done;
	if (regexec(&re, handp->dir, 0, NULL, 0) == 0)
		handp->matched = 1;
	regfree(&re);

	retval = 0;

done:
	free(expr);

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

/* new names */
static int USERNAME_CONTEXT_PRED(const char *string)
{
	return (int)(
		(strstr(string, TEMPLATE_USERNAME) != NULL) ||
		(strstr(string, TEMPLATE_USERID) != NULL)
	);
}

/* This will never match USER if USERNAME or USERID are found. */
static int USER_CONTEXT_PRED(const char *string)
{
	if (USERNAME_CONTEXT_PRED(string))
		return 0;

	return (int)(strstr(string, TEMPLATE_USER) != NULL);
}

static int STR_COMPARATOR(const void *a, const void *b)
{
	return strcmp((const char *) a, (const char *) b);
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

static char *replace_all(const char *str, const replacement_pair_t * repl)
{
	char *retval, *retval2;
	int i;

	if (!str || !repl)
		return NULL;

	retval = strdup(str);
	for (i = 0; retval != NULL && repl[i].search_for; i++) {
		retval2 = semanage_str_replace(repl[i].search_for,
					       repl[i].replace_with, retval, 0);
		free(retval);
		retval = retval2;
	}
	return retval;
}

static const char *extract_context(const char *line)
{
	const char *p = line;
	size_t off;

	off = strlen(p);
	p += off;
	/* consider trailing whitespaces */
	while (off > 0) {
		p--;
		off--;
		if (!isspace(*p))
			break;
	}
	if (off == 0)
		return NULL;

	/* find the last field in line */
	while (off > 0 && !isspace(*(p - 1))) {
		p--;
		off--;
	}
	return p;
}

static int check_line(genhomedircon_settings_t * s, const char *line)
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
		result = sepol_context_check(s->h_semanage->sepolh,
					     s->policydb, ctx_record);
		sepol_context_free(ctx_record);
	}
	return result;
}

static int write_replacements(genhomedircon_settings_t * s, FILE * out,
			      const semanage_list_t * tpl,
			      const replacement_pair_t *repl)
{
	char *line;

	for (; tpl; tpl = tpl->next) {
		line = replace_all(tpl->data, repl);
		if (!line)
			goto fail;
		if (check_line(s, line) == STATUS_SUCCESS) {
			if (fprintf(out, "%s\n", line) < 0)
				goto fail;
		}
		free(line);
	}
	return STATUS_SUCCESS;

      fail:
	free(line);
	return STATUS_ERR;
}

static int write_contexts(genhomedircon_settings_t *s, FILE *out,
			  semanage_list_t *tpl, const replacement_pair_t *repl,
			  const genhomedircon_user_entry_t *user)
{
	char *line, *temp;
	sepol_context_t *context = NULL;
	char *new_context_str = NULL;

	for (; tpl; tpl = tpl->next) {
		line = replace_all(tpl->data, repl);
		if (!line) {
			goto fail;
		}

		const char *old_context_str = extract_context(line);
		if (!old_context_str) {
			goto fail;
		}

		if (strcmp(old_context_str, CONTEXT_NONE) == 0) {
			if (check_line(s, line) == STATUS_SUCCESS &&
			    fprintf(out, "%s\n", line) < 0) {
				goto fail;
			}
			free(line);
			continue;
		}

		sepol_handle_t *sepolh = s->h_semanage->sepolh;

		if (sepol_context_from_string(sepolh, old_context_str,
					      &context) < 0) {
			goto fail;
		}

		if (sepol_context_set_user(sepolh, context, user->sename) < 0) {
			goto fail;
		}

		if (sepol_policydb_mls_enabled(s->policydb) &&
		    sepol_context_set_mls(sepolh, context, user->level) < 0) {
			goto fail;
		}

		if (user->homedir_role &&
		    sepol_context_set_role(sepolh, context, user->homedir_role) < 0) {
			goto fail;
		}

		if (sepol_context_to_string(sepolh, context,
					    &new_context_str) < 0) {
			goto fail;
		}

		temp = semanage_str_replace(old_context_str, new_context_str,
					    line, 1);
		if (!temp) {
			goto fail;
		}
		free(line);
		line = temp;

		if (check_line(s, line) == STATUS_SUCCESS) {
			if (fprintf(out, "%s\n", line) < 0)
				goto fail;
		}

		free(line);
		sepol_context_free(context);
		free(new_context_str);
	}

	return STATUS_SUCCESS;
fail:
	free(line);
	sepol_context_free(context);
	free(new_context_str);
	return STATUS_ERR;
}

static int write_home_dir_context(genhomedircon_settings_t * s, FILE * out,
				  semanage_list_t * tpl, const genhomedircon_user_entry_t *user)
{
	replacement_pair_t repl[] = {
		{.search_for = TEMPLATE_HOME_DIR,.replace_with = user->home},
		{.search_for = TEMPLATE_ROLE,.replace_with = user->prefix},
		{NULL, NULL}
	};

	if (strcmp(user->name, FALLBACK_NAME) == 0) {
		if (fprintf(out, COMMENT_USER_HOME_CONTEXT, FALLBACK_SENAME) < 0)
			return STATUS_ERR;
	} else {
		if (fprintf(out, COMMENT_USER_HOME_CONTEXT, user->name) < 0)
			return STATUS_ERR;
	}

	return write_contexts(s, out, tpl, repl, user);
}

static int write_home_root_context(genhomedircon_settings_t * s, FILE * out,
				   semanage_list_t * tpl, char *homedir)
{
	replacement_pair_t repl[] = {
		{.search_for = TEMPLATE_HOME_ROOT,.replace_with = homedir},
		{NULL, NULL}
	};

	return write_replacements(s, out, tpl, repl);
}

static int write_username_context(genhomedircon_settings_t * s, FILE * out,
				  semanage_list_t * tpl,
				  const genhomedircon_user_entry_t *user)
{
	replacement_pair_t repl[] = {
		{.search_for = TEMPLATE_USERNAME,.replace_with = user->name},
		{.search_for = TEMPLATE_USERID,.replace_with = user->uid},
		{.search_for = TEMPLATE_ROLE,.replace_with = user->prefix},
		{NULL, NULL}
	};

	return write_contexts(s, out, tpl, repl, user);
}

static int write_user_context(genhomedircon_settings_t * s, FILE * out,
			      semanage_list_t * tpl, const genhomedircon_user_entry_t *user)
{
	replacement_pair_t repl[] = {
		{.search_for = TEMPLATE_USER,.replace_with = user->name},
		{.search_for = TEMPLATE_ROLE,.replace_with = user->prefix},
		{NULL, NULL}
	};

	return write_contexts(s, out, tpl, repl, user);
}

static int seuser_sort_func(const void *arg1, const void *arg2)
{
	const semanage_seuser_t **u1 = (const semanage_seuser_t **) arg1;
	const semanage_seuser_t **u2 = (const semanage_seuser_t **) arg2;;
	const char *name1 = semanage_seuser_get_name(*u1);
	const char *name2 = semanage_seuser_get_name(*u2);

	if (name1[0] == '%' && name2[0] == '%') {
		return 0;
	} else if (name1[0] == '%') {
		return 1;
	} else if (name2[0] == '%') {
		return -1;
	}

	return strcmp(name1, name2);
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
			   const char *u, const char *g, const char *sen,
			   const char *pre, const char *h, const char *l,
			   const char *ln, const char *hd_role)
{
	genhomedircon_user_entry_t *temp = NULL;
	char *name = NULL;
	char *uid = NULL;
	char *gid = NULL;
	char *sename = NULL;
	char *prefix = NULL;
	char *home = NULL;
	char *level = NULL;
	char *lname = NULL;
	char *homedir_role = NULL;

	temp = malloc(sizeof(genhomedircon_user_entry_t));
	if (!temp)
		goto cleanup;
	name = strdup(n);
	if (!name)
		goto cleanup;
	uid = strdup(u);
	if (!uid)
		goto cleanup;
	gid = strdup(g);
	if (!gid)
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
	lname = strdup(ln);
	if (!lname)
		goto cleanup;
	if (hd_role) {
		homedir_role = strdup(hd_role);
		if (!homedir_role)
			goto cleanup;
	}

	temp->name = name;
	temp->uid = uid;
	temp->gid = gid;
	temp->sename = sename;
	temp->prefix = prefix;
	temp->home = home;
	temp->level = level;
	temp->login = lname;
	temp->homedir_role = homedir_role;
	temp->next = (*list);
	(*list) = temp;

	return STATUS_SUCCESS;

      cleanup:
	free(name);
	free(uid);
	free(gid);
	free(sename);
	free(prefix);
	free(home);
	free(level);
	free(lname);
	free(homedir_role);
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
	free(temp->uid);
	free(temp->gid);
	free(temp->sename);
	free(temp->prefix);
	free(temp->home);
	free(temp->level);
	free(temp->login);
	free(temp->homedir_role);
	free(temp);
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
	const char *homedir_role = NULL;
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
				level = FALLBACK_LEVEL;
			}
			else
			{
				prefix = semanage_user_get_prefix(u);
				level = semanage_user_get_mlslevel(u);
				if (!level)
					level = FALLBACK_LEVEL;
			}

			if (prefix_is_homedir_role(u, prefix)) {
				homedir_role = prefix;
			}

			if (push_user_entry(&(s->fallback), FALLBACK_NAME,
					    FALLBACK_UIDGID, FALLBACK_UIDGID,
					    seuname, prefix, "", level,
					    FALLBACK_NAME, homedir_role) != 0)
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

static genhomedircon_user_entry_t *find_user(genhomedircon_user_entry_t *head,
					     const char *name)
{
	for(; head; head = head->next) {
		if (strcmp(head->name, name) == 0) {
			return head;
		}
	}

	return NULL;
}

static int add_user(genhomedircon_settings_t * s,
		    genhomedircon_user_entry_t **head,
		    semanage_user_t *user,
		    const char *name,
		    const char *sename,
		    const char *selogin)
{
	if (selogin[0] == '%') {
		genhomedircon_user_entry_t *orig = find_user(*head, name);
		if (orig != NULL && orig->login[0] == '%') {
			ERR(s->h_semanage, "User %s is already mapped to"
			    " group %s, but also belongs to group %s. Add an"
			    " explicit mapping for this user to"
			    " override group mappings.",
			    name, orig->login + 1, selogin + 1);
			return STATUS_ERR;
		} else if (orig != NULL) {
			// user mappings take precedence
			return STATUS_SUCCESS;
		}
	}

	int retval = STATUS_ERR;

	char *rbuf = NULL;
	long rbuflen;
	struct passwd pwstorage, *pwent = NULL;
	const char *prefix = NULL;
	const char *level = NULL;
	const char *homedir_role = NULL;
	char uid[11];
	char gid[11];

	/* Allocate space for the getpwnam_r buffer */
	rbuflen = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (rbuflen <= 0)
		goto cleanup;
	rbuf = malloc(rbuflen);
	if (rbuf == NULL)
		goto cleanup;

	if (user) {
		prefix = semanage_user_get_prefix(user);
		level = semanage_user_get_mlslevel(user);

		if (!level) {
			level = FALLBACK_LEVEL;
		}
	} else {
		prefix = name;
		level = FALLBACK_LEVEL;
	}

	if (prefix_is_homedir_role(user, prefix)) {
		homedir_role = prefix;
	}

	retval = getpwnam_r(name, &pwstorage, rbuf, rbuflen, &pwent);
	if (retval != 0 || pwent == NULL) {
		if (retval != 0 && retval != ENOENT) {
			goto cleanup;
		}

		WARN(s->h_semanage,
		     "user %s not in password file", name);
		retval = STATUS_SUCCESS;
		goto cleanup;
	}

	int len = strlen(pwent->pw_dir) -1;
	for(; len > 0 && pwent->pw_dir[len] == '/'; len--) {
		pwent->pw_dir[len] = '\0';
	}

	if (strcmp(pwent->pw_dir, "/") == 0) {
		/* don't relabel / genhomdircon checked to see if root
		 * was the user and if so, set his home directory to
		 * /root */
		retval = STATUS_SUCCESS;
		goto cleanup;
	}

	if (ignore(pwent->pw_dir)) {
		retval = STATUS_SUCCESS;
		goto cleanup;
	}

	len = snprintf(uid, sizeof(uid), "%u", pwent->pw_uid);
	if (len < 0 || len >= (int)sizeof(uid)) {
		goto cleanup;
	}

	len = snprintf(gid, sizeof(gid), "%u", pwent->pw_gid);
	if (len < 0 || len >= (int)sizeof(gid)) {
		goto cleanup;
	}

	retval = push_user_entry(head, name, uid, gid, sename, prefix,
				pwent->pw_dir, level, selogin, homedir_role);
cleanup:
	free(rbuf);
	return retval;
}

static int get_group_users(genhomedircon_settings_t * s,
			  genhomedircon_user_entry_t **head,
			  semanage_user_t *user,
			  const char *sename,
			  const char *selogin)
{
	int retval = STATUS_ERR;
	unsigned int i;

	long grbuflen;
	char *grbuf = NULL;
	struct group grstorage, *group = NULL;

	long prbuflen;
	char *pwbuf = NULL;
	struct passwd pwstorage, *pw = NULL;

	grbuflen = sysconf(_SC_GETGR_R_SIZE_MAX);
	if (grbuflen <= 0)
		goto cleanup;
	grbuf = malloc(grbuflen);
	if (grbuf == NULL)
		goto cleanup;

	const char *grname = selogin + 1;

	if (getgrnam_r(grname, &grstorage, grbuf,
			(size_t) grbuflen, &group) != 0) {
		goto cleanup;
	}

	if (group == NULL) {
		ERR(s->h_semanage, "Can't find group named %s\n", grname);
		goto cleanup;
	}

	size_t nmembers = 0;
	char **members = group->gr_mem;

	while (*members != NULL) {
		nmembers++;
		members++;
	}

	for (i = 0; i < nmembers; i++) {
		const char *uname = group->gr_mem[i];

		if (add_user(s, head, user, uname, sename, selogin) < 0) {
			goto cleanup;
		}
	}

	prbuflen = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (prbuflen <= 0)
		goto cleanup;
	pwbuf = malloc(prbuflen);
	if (pwbuf == NULL)
		goto cleanup;

	setpwent();
	while ((retval = getpwent_r(&pwstorage, pwbuf, prbuflen, &pw)) == 0) {
		// skip users who also have this group as their
		// primary group
		if (lfind(pw->pw_name, group->gr_mem, &nmembers,
			  sizeof(char *), &STR_COMPARATOR)) {
			continue;
		}

		if (group->gr_gid == pw->pw_gid) {
			if (add_user(s, head, user, pw->pw_name,
				     sename, selogin) < 0) {
				goto cleanup;
			}
		}
	}

	retval = STATUS_SUCCESS;
cleanup:
	endpwent();
	free(pwbuf);
	free(grbuf);

	return retval;
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
	unsigned int i;
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

	qsort(seuser_list, nseusers, sizeof(semanage_seuser_t *),
	      &seuser_sort_func);
	qsort(user_list, nusers, sizeof(semanage_user_t *),
	      (int (*)(const void *, const void *))&user_sort_func);

	for (i = 0; i < nseusers; i++) {
		seuname = semanage_seuser_get_sename(seuser_list[i]);
		name = semanage_seuser_get_name(seuser_list[i]);

		if (strcmp(name, DEFAULT_LOGIN) == 0)
			continue;

		/* find the user structure given the name */
		u = bsearch(seuname, user_list, nusers, sizeof(semanage_user_t *),
			    (int (*)(const void *, const void *))
			    &name_user_cmp);

		/* %groupname syntax */
		if (name[0] == '%') {
			retval = get_group_users(s, &head, *u, seuname,
						name);
		} else {
			retval = add_user(s, &head, *u, name,
					  seuname, name);
		}

		if (retval != 0) {
			*errors = STATUS_ERR;
			goto cleanup;
		}
	}

      cleanup:
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
				      semanage_list_t * username_context_tpl,
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
		if (write_home_dir_context(s, out, homedir_context_tpl, users))
			goto err;
		if (write_username_context(s, out, username_context_tpl, users))
			goto err;
		if (write_user_context(s, out, user_context_tpl, users))
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
	semanage_list_t *homedir_context_tpl = NULL;
	semanage_list_t *homeroot_context_tpl = NULL;
	semanage_list_t *username_context_tpl = NULL;
	semanage_list_t *user_context_tpl = NULL;
	int retval = STATUS_SUCCESS;

	homedir_context_tpl = make_template(s, &HOME_DIR_PRED);
	homeroot_context_tpl = make_template(s, &HOME_ROOT_PRED);
	username_context_tpl = make_template(s, &USERNAME_CONTEXT_PRED);
	user_context_tpl = make_template(s, &USER_CONTEXT_PRED);

	if (!homedir_context_tpl
	 && !homeroot_context_tpl
	 && !username_context_tpl
	 && !user_context_tpl)
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
			char *temp = NULL;

			if (asprintf(&temp, "%s/%s", h->data, FALLBACK_NAME) < 0) {
				retval = STATUS_ERR;
				goto done;
			}

			free(s->fallback->home);
			s->fallback->home = temp;

			if (write_home_dir_context(s, out, homedir_context_tpl,
						   s->fallback) != STATUS_SUCCESS) {
				free(temp);
				s->fallback->home = NULL;
				retval = STATUS_ERR;
				goto done;
			}
			if (write_home_root_context(s, out,
						    homeroot_context_tpl,
						    h->data) != STATUS_SUCCESS) {
				free(temp);
				s->fallback->home = NULL;
				retval = STATUS_ERR;
				goto done;
			}

			free(temp);
			s->fallback->home = NULL;
		}
	}
	if (user_context_tpl || username_context_tpl) {
		if (write_username_context(s, out, username_context_tpl,
					   s->fallback) != STATUS_SUCCESS) {
			retval = STATUS_ERR;
			goto done;
		}

		if (write_user_context(s, out, user_context_tpl,
				       s->fallback) != STATUS_SUCCESS) {
			retval = STATUS_ERR;
			goto done;
		}

		if (write_gen_home_dir_context(s, out, username_context_tpl,
					       user_context_tpl, homedir_context_tpl)
				!= STATUS_SUCCESS) {
			retval = STATUS_ERR;
		}
	}

done:
	/* Cleanup */
	semanage_list_destroy(&homedirs);
	semanage_list_destroy(&username_context_tpl);
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

	s.fallback = calloc(1, sizeof(genhomedircon_user_entry_t));
	if (s.fallback == NULL) {
		retval = STATUS_ERR;
		goto done;
	}

	s.fallback->name = strdup(FALLBACK_NAME);
	s.fallback->sename = strdup(FALLBACK_SENAME);
	s.fallback->prefix = strdup(FALLBACK_PREFIX);
	s.fallback->level = strdup(FALLBACK_LEVEL);
	if (s.fallback->name == NULL
	 || s.fallback->sename == NULL
	 || s.fallback->prefix == NULL
	 || s.fallback->level == NULL) {
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

	pop_user_entry(&(s.fallback));
	ignore_free();

	return retval;
}
