#include "restore.h"

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
		perror(opts->selabel_opt_path);
		exit(1);
	}

	opts->restorecon_flags = 0;
	opts->restorecon_flags =
		opts->nochange | opts->verbose | opts->progress |
		opts->set_specctx | opts->add_assoc | opts->ignore_digest |
		opts->recurse | opts->userealpath | opts->xdev |
		opts->abort_on_error | opts->syslog_changes |
		opts->log_matches | opts->ignore_noent | opts->ignore_mounts |
		opts->skip_multilink;

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
}
