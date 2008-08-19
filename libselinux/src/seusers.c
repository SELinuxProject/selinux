#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <ctype.h>
#include <selinux/selinux.h>
#include <selinux/context.h>
#include "selinux_internal.h"

/* Process line from seusers.conf and split into its fields.
   Returns 0 on success, -1 on comments, and -2 on error. */
static int process_seusers(const char *buffer,
			   char **luserp,
			   char **seuserp, char **levelp, int mls_enabled)
{
	char *newbuf = strdup(buffer);
	char *luser = NULL, *seuser = NULL, *level = NULL;
	char *start, *end;
	int mls_found = 1;

	if (!newbuf)
		goto err;

	start = newbuf;
	while (isspace(*start))
		start++;
	if (*start == '#' || *start == 0) {
		free(newbuf);
		return -1;	/* Comment or empty line, skip over */
	}
	end = strchr(start, ':');
	if (!end)
		goto err;
	*end = 0;

	luser = strdup(start);
	if (!luser)
		goto err;

	start = end + 1;
	end = strchr(start, ':');
	if (!end) {
		mls_found = 0;

		end = start;
		while (*end && !isspace(*end))
			end++;
	}
	*end = 0;

	seuser = strdup(start);
	if (!seuser)
		goto err;

	if (!strcmp(seuser, ""))
		goto err;

	/* Skip MLS if disabled, or missing. */
	if (!mls_enabled || !mls_found)
		goto out;

	start = ++end;
	while (*end && !isspace(*end))
		end++;
	*end = 0;

	level = strdup(start);
	if (!level)
		goto err;

	if (!strcmp(level, ""))
		goto err;

      out:
	free(newbuf);
	*luserp = luser;
	*seuserp = seuser;
	*levelp = level;
	return 0;
      err:
	free(newbuf);
	free(luser);
	free(seuser);
	free(level);
	return -2;		/* error */
}

int require_seusers hidden = 0;

int getseuserbyname(const char *name, char **r_seuser, char **r_level)
{
	FILE *cfg = NULL;
	size_t size = 0;
	char *buffer = NULL;
	int rc;
	unsigned long lineno = 0;
	int mls_enabled = is_selinux_mls_enabled();

	char *username = NULL;
	char *seuser = NULL;
	char *level = NULL;
	char *defaultseuser = NULL;
	char *defaultlevel = NULL;

	cfg = fopen(selinux_usersconf_path(), "r");
	if (!cfg)
		goto nomatch;

	__fsetlocking(cfg, FSETLOCKING_BYCALLER);
	while (getline(&buffer, &size, cfg) > 0) {
		++lineno;
		rc = process_seusers(buffer, &username, &seuser, &level,
				     mls_enabled);
		if (rc == -1)
			continue;	/* comment, skip */
		if (rc == -2) {
			fprintf(stderr, "%s:  error on line %lu, skipping...\n",
				selinux_usersconf_path(), lineno);
			continue;
		}

		if (!strcmp(username, name))
			break;

		if (!defaultseuser && !strcmp(username, "__default__")) {
			free(username);
			defaultseuser = seuser;
			defaultlevel = level;
		} else {
			free(username);
			free(seuser);
			free(level);
		}
		seuser = NULL;
	}

	if (buffer)
		free(buffer);
	fclose(cfg);

	if (seuser) {
		free(username);
		free(defaultseuser);
		free(defaultlevel);
		*r_seuser = seuser;
		*r_level = level;
		return 0;
	}

	if (defaultseuser) {
		*r_seuser = defaultseuser;
		*r_level = defaultlevel;
		return 0;
	}

      nomatch:
	if (require_seusers)
		return -1;

	/* Fall back to the Linux username and no level. */
	*r_seuser = strdup(name);
	if (!(*r_seuser))
		return -1;
	*r_level = NULL;
	return 0;
}
