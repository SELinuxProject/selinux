/*
 * Note that the restorecond(8) service build links with these functions.
 * Therefore any changes here should also be tested against that utility.
 */

#include "restore.h"
#include <glob.h>

#ifndef GLOB_BRACE
#define GLOB_BRACE 0
#endif

#ifndef GLOB_TILDE
#define GLOB_TILDE 0
#endif

char **exclude_list;
int exclude_count;

void restore_init(struct restore_opts *opts)
{
	int rc;

	struct selinux_opt selinux_opts[] = {
		{ SELABEL_OPT_VALIDATE, opts->selabel_opt_validate },
		{ SELABEL_OPT_PATH, opts->selabel_opt_path },
		{ SELABEL_OPT_DIGEST, opts->selabel_opt_digest }
	};

	opts->hnd = selabel_open(SELABEL_CTX_FILE, selinux_opts, 3);
	if (!opts->hnd) {
		perror(opts->selabel_opt_path ? opts->selabel_opt_path : selinux_file_context_path());
		exit(1);
	}

	opts->restorecon_flags = 0;
	opts->restorecon_flags = opts->nochange | opts->verbose |
			   opts->progress | opts->set_specctx  |
			   opts->add_assoc | opts->ignore_digest |
			   opts->recurse | opts->userealpath |
			   opts->xdev | opts->abort_on_error |
			   opts->syslog_changes | opts->log_matches |
			   opts->ignore_noent | opts->ignore_mounts |
			   opts->mass_relabel | opts->conflict_error |
			   opts->count_errors;

	/* Use setfiles, restorecon and restorecond own handles */
	selinux_restorecon_set_sehandle(opts->hnd);

	if (opts->rootpath) {
		rc = selinux_restorecon_set_alt_rootpath(opts->rootpath);
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

int process_glob(char *name, struct restore_opts *opts, size_t nthreads,
		 long unsigned *skipped_errors)
{
	glob_t globbuf;
	size_t i = 0;
	int len, rc, errors;

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
		rc = selinux_restorecon_parallel(globbuf.gl_pathv[i],
						 opts->restorecon_flags,
						 nthreads);
		if (rc < 0)
			errors = rc;
		else if (opts->restorecon_flags & SELINUX_RESTORECON_COUNT_ERRORS)
			*skipped_errors += selinux_restorecon_get_skipped_errors();
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
