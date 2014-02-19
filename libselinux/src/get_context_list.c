#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdio_ext.h>
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

hidden_def(get_default_context_with_role)

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

static int find_partialcon(char ** list,
			   unsigned int nreach, char *part)
{
	const char *conrole, *contype;
	char *partrole, *parttype, *ptr;
	context_t con;
	unsigned int i;

	partrole = part;
	ptr = part;
	while (*ptr && !isspace(*ptr) && *ptr != ':')
		ptr++;
	if (*ptr != ':')
		return -1;
	*ptr++ = 0;
	parttype = ptr;
	while (*ptr && !isspace(*ptr) && *ptr != ':')
		ptr++;
	*ptr = 0;

	for (i = 0; i < nreach; i++) {
		con = context_new(list[i]);
		if (!con)
			return -1;
		conrole = context_role_get(con);
		contype = context_type_get(con);
		if (!conrole || !contype) {
			context_free(con);
			return -1;
		}
		if (!strcmp(conrole, partrole) && !strcmp(contype, parttype)) {
			context_free(con);
			return i;
		}
		context_free(con);
	}

	return -1;
}

static int get_context_order(FILE * fp,
			     char * fromcon,
			     char ** reachable,
			     unsigned int nreach,
			     unsigned int *ordering, unsigned int *nordered)
{
	char *start, *end = NULL;
	char *line = NULL;
	size_t line_len = 0;
	ssize_t len;
	int found = 0;
	const char *fromrole, *fromtype;
	char *linerole, *linetype;
	unsigned int i;
	context_t con;
	int rc;

	errno = -EINVAL;

	/* Extract the role and type of the fromcon for matching.
	   User identity and MLS range can be variable. */
	con = context_new(fromcon);
	if (!con)
		return -1;
	fromrole = context_role_get(con);
	fromtype = context_type_get(con);
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

		/* Check for a match in the reachable list. */
		rc = find_partialcon(reachable, nreach, start);
		if (rc < 0) {
			/* No match, skip it. */
			start = end;
			continue;
		}

		/* If a match is found and the entry is not already ordered
		   (e.g. due to prior match in prior config file), then set
		   the ordering for it. */
		i = rc;
		if (ordering[i] == nreach)
			ordering[i] = (*nordered)++;
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

	fp = fopen(selinux_failsafe_context_path(), "r");
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

struct context_order {
	char * con;
	unsigned int order;
};

static int order_compare(const void *A, const void *B)
{
	const struct context_order *c1 = A, *c2 = B;
	if (c1->order < c2->order)
		return -1;
	else if (c1->order > c2->order)
		return 1;
	return strcmp(c1->con, c2->con);
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

hidden_def(get_ordered_context_list_with_level)

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
	unsigned int *ordering = NULL;
	struct context_order *co = NULL;
	char **ptr;
	int rc = 0;
	unsigned int nreach = 0, nordered = 0, freefrom = 0, i;
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

	/* Determine the set of reachable contexts for the user. */
	rc = security_compute_user(fromcon, user, &reachable);
	if (rc < 0)
		goto failsafe;
	nreach = 0;
	for (ptr = reachable; *ptr; ptr++)
		nreach++;
	if (!nreach)
		goto failsafe;

	/* Initialize ordering array. */
	ordering = malloc(nreach * sizeof(unsigned int));
	if (!ordering)
		goto failsafe;
	for (i = 0; i < nreach; i++)
		ordering[i] = nreach;

	/* Determine the ordering to apply from the optional per-user config
	   and from the global config. */
	fname_len = strlen(user_contexts_path) + strlen(user) + 2;
	fname = malloc(fname_len);
	if (!fname)
		goto failsafe;
	snprintf(fname, fname_len, "%s%s", user_contexts_path, user);
	fp = fopen(fname, "r");
	if (fp) {
		__fsetlocking(fp, FSETLOCKING_BYCALLER);
		rc = get_context_order(fp, fromcon, reachable, nreach, ordering,
				       &nordered);
		fclose(fp);
		if (rc < 0 && errno != ENOENT) {
			fprintf(stderr,
				"%s:  error in processing configuration file %s\n",
				__FUNCTION__, fname);
			/* Fall through, try global config */
		}
	}
	free(fname);
	fp = fopen(selinux_default_context_path(), "r");
	if (fp) {
		__fsetlocking(fp, FSETLOCKING_BYCALLER);
		rc = get_context_order(fp, fromcon, reachable, nreach, ordering,
				       &nordered);
		fclose(fp);
		if (rc < 0 && errno != ENOENT) {
			fprintf(stderr,
				"%s:  error in processing configuration file %s\n",
				__FUNCTION__, selinux_default_context_path());
			/* Fall through */
		}
		rc = 0;
	}

	if (!nordered)
		goto failsafe;

	/* Apply the ordering. */
	co = malloc(nreach * sizeof(struct context_order));
	if (!co)
		goto failsafe;
	for (i = 0; i < nreach; i++) {
		co[i].con = reachable[i];
		co[i].order = ordering[i];
	}
	qsort(co, nreach, sizeof(struct context_order), order_compare);
	for (i = 0; i < nreach; i++)
		reachable[i] = co[i].con;
	free(co);

	/* Only report the ordered entries to the caller. */
	if (nordered <= nreach) {
		for (i = nordered; i < nreach; i++)
			free(reachable[i]);
		reachable[nordered] = NULL;
		rc = nordered;
	}

      out:
	if (rc > 0)
		*list = reachable;
	else
		freeconary(reachable);

	free(ordering);
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
	rc = 1;			/* one context in the list */
	goto out;
}

hidden_def(get_ordered_context_list)
