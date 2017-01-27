/*
 * Note that the restorecond(8) service build links with these functions.
 * Therefore any changes here should also be tested against that utility.
 */

#include "restore.h"
#include <glob.h>

char **exclude_list;
int exclude_count;

struct restore_opts *r_opts;

void restore_init(struct restore_opts *opts)
{
	int rc;

	r_opts = opts;
	struct selinux_opt selinux_opts[] = {
		{ SELABEL_OPT_VALIDATE, r_opts->selabel_opt_validate },
		{ SELABEL_OPT_PATH, r_opts->selabel_opt_path },
		{ SELABEL_OPT_DIGEST, r_opts->selabel_opt_digest }
	};

	r_opts->hnd = selabel_open(SELABEL_CTX_FILE, selinux_opts, 3);
	if (!r_opts->hnd) {
		perror(r_opts->selabel_opt_path);
		exit(1);
	}

	r_opts->restorecon_flags = 0;
	r_opts->restorecon_flags = r_opts->nochange | r_opts->verbose |
			   r_opts->progress | r_opts->set_specctx  |
			   r_opts->add_assoc | r_opts->ignore_digest |
			   r_opts->recurse | r_opts->userealpath |
			   r_opts->xdev | r_opts->abort_on_error |
			   r_opts->syslog_changes | r_opts->log_matches |
			   r_opts->ignore_noent | r_opts->ignore_mounts |
			   r_opts->mass_relabel;

	/* Use setfiles, restorecon and restorecond own handles */
	selinux_restorecon_set_sehandle(r_opts->hnd);

	if (r_opts->rootpath) {
		rc = selinux_restorecon_set_alt_rootpath(r_opts->rootpath);
		if (rc) {
			fprintf(stderr,
				"selinux_restorecon_set_alt_rootpath error: %s.\n",
				strerror(errno));
			exit(-1);
		}
	}

	if (exclude_list)
		selinux_restorecon_set_exclude_list
						 ((const char **)exclude_list);
}

void restore_finish(void)
{
	int i;

	if (exclude_list) {
		for (i = 0; exclude_list[i]; i++)
			free(exclude_list[i]);
		free(exclude_list);
	}
}

int process_glob(char *name, struct restore_opts *opts)
{
	glob_t globbuf;
	size_t i = 0;
	int len, rc, errors;

	r_opts = opts;
	memset(&globbuf, 0, sizeof(globbuf));

	errors = glob(name, GLOB_TILDE | GLOB_PERIOD |
			  GLOB_NOCHECK | GLOB_BRACE, NULL, &globbuf);
	if (errors)
		return errors;

	for (i = 0; i < globbuf.gl_pathc; i++) {
		len = strlen(globbuf.gl_pathv[i]) - 2;
		if (len > 0 && strcmp(&globbuf.gl_pathv[i][len--], "/.") == 0)
			continue;
		if (len > 0 && strcmp(&globbuf.gl_pathv[i][len], "/..") == 0)
			continue;
		rc = selinux_restorecon(globbuf.gl_pathv[i],
					r_opts->restorecon_flags);
		if (rc < 0)
			errors = rc;
	}

	globfree(&globbuf);

	return errors;
}

void add_exclude(const char *directory)
{
	char **tmp_list;

	if (directory == NULL || directory[0] != '/') {
		fprintf(stderr, "Full path required for exclude: %s.\n",
			    directory);
		exit(-1);
	}

	/* Add another two entries, one for directory, and the other to
	 * terminate the list.
	 */
	tmp_list = realloc(exclude_list, sizeof(char *) * (exclude_count + 2));
	if (!tmp_list) {
		fprintf(stderr, "realloc failed while excluding %s.\n",
			    directory);
		exit(-1);
	}
	exclude_list = tmp_list;

	exclude_list[exclude_count] = strdup(directory);
	if (!exclude_list[exclude_count]) {
		fprintf(stderr, "strdup failed while excluding %s.\n",
			    directory);
		exit(-1);
	}
	exclude_count++;
	exclude_list[exclude_count] = NULL;
}
