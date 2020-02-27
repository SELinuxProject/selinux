#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pwd.h>
#include "selinux_internal.h"
#include "context_internal.h"
#include "get_context_list_internal.h"

int get_default_context_with_role(const char *user,
				  const char *role,
				  char * fromcon,
				  char ** newcon)
{
	char **conary;
	char **ptr;
	context_t con;
	const char *role2;
	int rc;

	rc = get_ordered_context_list(user, fromcon, &conary);
	if (rc <= 0)
		return -1;

	for (ptr = conary; *ptr; ptr++) {
		con = context_new(*ptr);
		if (!con)
			continue;
		role2 = context_role_get(con);
		if (role2 && !strcmp(role, role2)) {
			context_free(con);
			break;
		}
		context_free(con);
	}

	rc = -1;
	if (!(*ptr)) {
		errno = EINVAL;
		goto out;
	}
	*newcon = strdup(*ptr);
	if (!(*newcon))
		goto out;
	rc = 0;
      out:
	freeconary(conary);
	return rc;
}


int get_default_context_with_rolelevel(const char *user,
				       const char *role,
				       const char *level,
				       char * fromcon,
				       char ** newcon)
{

	int rc = 0;
	int freefrom = 0;
	context_t con;
	char *newfromcon;
	if (!level)
		return get_default_context_with_role(user, role, fromcon,
						     newcon);

	if (!fromcon) {
		rc = getcon(&fromcon);
		if (rc < 0)
			return rc;
		freefrom = 1;
	}

	rc = -1;
	con = context_new(fromcon);
	if (!con)
		goto out;

	if (context_range_set(con, level))
		goto out;

	newfromcon = context_str(con);
	if (!newfromcon)
		goto out;

	rc = get_default_context_with_role(user, role, newfromcon, newcon);

      out:
	context_free(con);
	if (freefrom)
		freecon(fromcon);
	return rc;

}

int get_default_context(const char *user,
			char * fromcon, char ** newcon)
{
	char **conary;
	int rc;

	rc = get_ordered_context_list(user, fromcon, &conary);
	if (rc <= 0)
		return -1;

	*newcon = strdup(conary[0]);
	freeconary(conary);
	if (!(*newcon))
		return -1;
	return 0;
}

static int is_in_reachable(char **reachable, const char *usercon_str)
{
	if (!reachable)
		return 0;

	for (; *reachable != NULL; reachable++) {
		if (strcmp(*reachable, usercon_str) == 0) {
			return 1;
		}
	}
	return 0;
}

static int get_context_user(FILE * fp,
			     char * fromcon,
			     const char * user,
			     char ***reachable,
			     unsigned int *nreachable)
{
	char *start, *end = NULL;
	char *line = NULL;
	size_t line_len = 0, usercon_len;
	size_t user_len = strlen(user);
	ssize_t len;
	int found = 0;
	const char *fromrole, *fromtype, *fromlevel;
	char *linerole, *linetype;
	char **new_reachable = NULL;
	char *usercon_str;
	context_t con;
	context_t usercon;

	int rc;

	errno = EINVAL;

	/* Extract the role and type of the fromcon for matching.
	   User identity and MLS range can be variable. */
	con = context_new(fromcon);
	if (!con)
		return -1;
	fromrole = context_role_get(con);
	fromtype = context_type_get(con);
	fromlevel = context_range_get(con);
	if (!fromrole || !fromtype) {
		context_free(con);
		return -1;
	}

	while ((len = getline(&line, &line_len, fp)) > 0) {
		if (line[len - 1] == '\n')
			line[len - 1] = 0;

		/* Skip leading whitespace. */
		start = line;
		while (*start && isspace(*start))
			start++;
		if (!(*start))
			continue;

		/* Find the end of the (partial) fromcon in the line. */
		end = start;
		while (*end && !isspace(*end))
			end++;
		if (!(*end))
			continue;

		/* Check for a match. */
		linerole = start;
		while (*start && !isspace(*start) && *start != ':')
			start++;
		if (*start != ':')
			continue;
		*start = 0;
		linetype = ++start;
		while (*start && !isspace(*start) && *start != ':')
			start++;
		if (!(*start))
			continue;
		*start = 0;
		if (!strcmp(fromrole, linerole) && !strcmp(fromtype, linetype)) {
			found = 1;
			break;
		}
	}

	if (!found) {
		errno = ENOENT;
		rc = -1;
		goto out;
	}

	start = ++end;
	while (*start) {
		/* Skip leading whitespace */
		while (*start && isspace(*start))
			start++;
		if (!(*start))
			break;

		/* Find the end of this partial context. */
		end = start;
		while (*end && !isspace(*end))
			end++;
		if (*end)
			*end++ = 0;

		/* Check whether a new context is valid */
		if (SIZE_MAX - user_len < strlen(start) + 2) {
			fprintf(stderr, "%s: one of partial contexts is too big\n", __FUNCTION__);
			errno = EINVAL;
			rc = -1;
			goto out;
		}
		usercon_len = user_len + strlen(start) + 2;
		usercon_str = malloc(usercon_len);
		if (!usercon_str) {
			rc = -1;
			goto out;
		}

		/* set range from fromcon in the new usercon */
		snprintf(usercon_str, usercon_len, "%s:%s", user, start);
		usercon = context_new(usercon_str);
		if (!usercon) {
			if (errno != EINVAL) {
				free(usercon_str);
				rc = -1;
				goto out;
			}
			fprintf(stderr,
				"%s: can't create a context from %s, skipping\n",
				__FUNCTION__, usercon_str);
			free(usercon_str);
			start = end;
			continue;
		}
		free(usercon_str);
		if (context_range_set(usercon, fromlevel) != 0) {
			context_free(usercon);
			rc = -1;
			goto out;
		}
		usercon_str = context_str(usercon);
		if (!usercon_str) {
			context_free(usercon);
			rc = -1;
			goto out;
		}

		/* check whether usercon is already in reachable */
		if (is_in_reachable(*reachable, usercon_str)) {
			context_free(usercon);
			start = end;
			continue;
		}
		if (security_check_context(usercon_str) == 0) {
			new_reachable = realloc(*reachable, (*nreachable + 2) * sizeof(char *));
			if (!new_reachable) {
				context_free(usercon);
				rc = -1;
				goto out;
			}
			*reachable = new_reachable;
			new_reachable[*nreachable] = strdup(usercon_str);
			if (new_reachable[*nreachable] == NULL) {
				context_free(usercon);
				rc = -1;
				goto out;
			}
			new_reachable[*nreachable + 1] = 0;
			*nreachable += 1;
		}
		context_free(usercon);
		start = end;
	}
	rc = 0;

      out:
	context_free(con);
	free(line);
	return rc;
}

static int get_failsafe_context(const char *user, char ** newcon)
{
	FILE *fp;
	char buf[255], *ptr;
	size_t plen, nlen;
	int rc;

	fp = fopen(selinux_failsafe_context_path(), "re");
	if (!fp)
		return -1;

	ptr = fgets_unlocked(buf, sizeof buf, fp);
	fclose(fp);

	if (!ptr)
		return -1;
	plen = strlen(ptr);
	if (buf[plen - 1] == '\n')
		buf[plen - 1] = 0;

	nlen = strlen(user) + 1 + plen + 1;
	*newcon = malloc(nlen);
	if (!(*newcon))
		return -1;
	rc = snprintf(*newcon, nlen, "%s:%s", user, ptr);
	if (rc < 0 || (size_t) rc >= nlen) {
		free(*newcon);
		*newcon = 0;
		return -1;
	}

	/* If possible, check the context to catch
	   errors early rather than waiting until the
	   caller tries to use setexeccon on the context.
	   But this may not always be possible, e.g. if
	   selinuxfs isn't mounted. */
	if (security_check_context(*newcon) && errno != ENOENT) {
		free(*newcon);
		*newcon = 0;
		return -1;
	}

	return 0;
}

int get_ordered_context_list_with_level(const char *user,
					const char *level,
					char * fromcon,
					char *** list)
{
	int rc;
	int freefrom = 0;
	context_t con;
	char *newfromcon;

	if (!level)
		return get_ordered_context_list(user, fromcon, list);

	if (!fromcon) {
		rc = getcon(&fromcon);
		if (rc < 0)
			return rc;
		freefrom = 1;
	}

	rc = -1;
	con = context_new(fromcon);
	if (!con)
		goto out;

	if (context_range_set(con, level))
		goto out;

	newfromcon = context_str(con);
	if (!newfromcon)
		goto out;

	rc = get_ordered_context_list(user, newfromcon, list);

      out:
	context_free(con);
	if (freefrom)
		freecon(fromcon);
	return rc;
}


int get_default_context_with_level(const char *user,
				   const char *level,
				   char * fromcon,
				   char ** newcon)
{
	char **conary;
	int rc;

	rc = get_ordered_context_list_with_level(user, level, fromcon, &conary);
	if (rc <= 0)
		return -1;

	*newcon = strdup(conary[0]);
	freeconary(conary);
	if (!(*newcon))
		return -1;
	return 0;
}

int get_ordered_context_list(const char *user,
			     char * fromcon,
			     char *** list)
{
	char **reachable = NULL;
	int rc = 0;
	unsigned nreachable = 0, freefrom = 0;
	FILE *fp;
	char *fname = NULL;
	size_t fname_len;
	const char *user_contexts_path = selinux_user_contexts_path();

	if (!fromcon) {
		/* Get the current context and use it for the starting context */
		rc = getcon(&fromcon);
		if (rc < 0)
			return rc;
		freefrom = 1;
	}

	/* Determine the ordering to apply from the optional per-user config
	   and from the global config. */
	fname_len = strlen(user_contexts_path) + strlen(user) + 2;
	fname = malloc(fname_len);
	if (!fname)
		goto failsafe;
	snprintf(fname, fname_len, "%s%s", user_contexts_path, user);
	fp = fopen(fname, "re");
	if (fp) {
		__fsetlocking(fp, FSETLOCKING_BYCALLER);
		rc = get_context_user(fp, fromcon, user, &reachable, &nreachable);

		fclose(fp);
		if (rc < 0 && errno != ENOENT) {
			fprintf(stderr,
				"%s:  error in processing configuration file %s\n",
				__FUNCTION__, fname);
			/* Fall through, try global config */
		}
	}
	free(fname);
	fp = fopen(selinux_default_context_path(), "re");
	if (fp) {
		__fsetlocking(fp, FSETLOCKING_BYCALLER);
		rc = get_context_user(fp, fromcon, user, &reachable, &nreachable);
		fclose(fp);
		if (rc < 0 && errno != ENOENT) {
			fprintf(stderr,
				"%s:  error in processing configuration file %s\n",
				__FUNCTION__, selinux_default_context_path());
			/* Fall through */
		}
	}

	if (!nreachable)
		goto failsafe;

      out:
	if (nreachable > 0) {
		*list = reachable;
		rc = nreachable;
	}
	else
		freeconary(reachable);

	if (freefrom)
		freecon(fromcon);

	return rc;

      failsafe:
	/* Unable to determine a reachable context list, try to fall back to
	   the "failsafe" context to at least permit root login
	   for emergency recovery if possible. */
	freeconary(reachable);
	reachable = malloc(2 * sizeof(char *));
	if (!reachable) {
		rc = -1;
		goto out;
	}
	reachable[0] = reachable[1] = 0;
	rc = get_failsafe_context(user, &reachable[0]);
	if (rc < 0) {
		freeconary(reachable);
		reachable = NULL;
		goto out;
	}
	nreachable = 1;			/* one context in the list */
	goto out;
}

