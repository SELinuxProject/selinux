#include "restore.h"
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio_ext.h>
#include <ctype.h>
#include <regex.h>
#include <sys/vfs.h>
#include <libgen.h>
#ifdef USE_AUDIT
#include <libaudit.h>

#ifndef AUDIT_FS_RELABEL
#define AUDIT_FS_RELABEL 2309
#endif
#endif

static char *policyfile;
static int warn_no_match;
static int null_terminated;
static int request_digest;
static struct restore_opts r_opts;

#define STAT_BLOCK_SIZE 1

#define SETFILES "setfiles"
#define RESTORECON "restorecon"
static int iamrestorecon;

/* Behavior flags determined based on setfiles vs. restorecon */
static int ctx_validate; /* Validate contexts */
static const char *altpath; /* Alternate path to file_contexts */

static __attribute__((__noreturn__)) void usage(const char *const name)
{
	if (iamrestorecon) {
		fprintf(stderr,
			"usage:  %s [-iIDFUmnprRv0xT] [-e excludedir] pathname...\n"
			"usage:  %s [-iIDFUmnprRv0xT] [-e excludedir] -f filename\n",
			name, name);
	} else {
		fprintf(stderr,
			"usage:  %s [-diIDlmnpqvACEFUWT] [-e excludedir] [-r alt_root_path] [-c policyfile] spec_file pathname...\n"
			"usage:  %s [-diIDlmnpqvACEFUWT] [-e excludedir] [-r alt_root_path] [-c policyfile] spec_file -f filename\n"
			"usage:  %s -s [-diIDlmnpqvAFUWT] spec_file\n",
			name, name, name);
	}
	exit(-1);
}

static void set_rootpath(const char *arg)
{
	if (strlen(arg) == 1 && strncmp(arg, "/", 1) == 0) {
		fprintf(stderr, "%s:  invalid alt_rootpath: %s\n",
			r_opts.progname, arg);
		exit(-1);
	}

	r_opts.rootpath = strdup(arg);
	if (!r_opts.rootpath) {
		fprintf(stderr,
			"%s:  insufficient memory for r_opts.rootpath\n",
			r_opts.progname);
		exit(-1);
	}
}

static int canoncon(char **contextp)
{
	char *context = *contextp, *tmpcon;
	int rc = 0;

	if (policyfile) {
		if (sepol_check_context(context) < 0) {
			fprintf(stderr, "invalid context %s\n", context);
			exit(-1);
		}
	} else if (security_canonicalize_context_raw(context, &tmpcon) == 0) {
		free(context);
		*contextp = tmpcon;
	} else if (errno != ENOENT) {
		rc = -1;
	}

	return rc;
}

#ifndef USE_AUDIT
static void audit_mass_relabel(int mass_relabel_errs __attribute__((unused)))
{
#else
static void audit_mass_relabel(int mass_relabel_errs)
{
	int audit_fd = -1;
	int rc = 0;

	audit_fd = audit_open();

	if (audit_fd < 0) {
		fprintf(stderr, "Error connecting to audit system: %s.\n",
			strerror(errno));
		return;
	}

	rc = audit_log_user_message(audit_fd, AUDIT_FS_RELABEL,
				    "op=mass relabel",
				    NULL, NULL, NULL, !mass_relabel_errs);
	if (rc <= 0) {
		fprintf(stderr, "Error sending audit message: %s.\n",
			strerror(errno));
		/* exit(-1); -- don't exit atm. as fix for eff_cap isn't
		 * in most kernels.
		 */
	}
	audit_close(audit_fd);
#endif
}

static int __attribute__ ((format(printf, 2, 3)))
log_callback(int type, const char *fmt, ...)
{
	int rc;
	FILE *out;
	va_list ap;

	if (type == SELINUX_INFO) {
		out = stdout;
	} else {
		out = stderr;
		fflush(stdout);
		fprintf(out, "%s: ", r_opts.progname);
	}
	va_start(ap, fmt);
	rc = vfprintf(out, fmt, ap);
	va_end(ap);
	return rc;
}

int main(int argc, char **argv)
{
	struct stat sb;
	int opt, i = 0;
	const char *input_filename = NULL;
	int use_input_file = 0;
	char *buf = NULL, *endptr;
	size_t buf_len, nthreads = 1;
	const char *base;
	int errors = 0;
	const char *ropts = "e:f:hiIDlmno:pqrsvFURW0xT:";
	const char *sopts = "c:de:f:hiIDlmno:pqr:svACEFUR:W0T:";
	const char *opts;
	union selinux_callback cb;
	long unsigned skipped_errors;

	/* Initialize variables */
	memset(&r_opts, 0, sizeof(r_opts));
	altpath = NULL;
	null_terminated = 0;
	warn_no_match = 0;
	request_digest = 0;
	policyfile = NULL;
	skipped_errors = 0;

	if (!argv[0]) {
		fprintf(stderr, "Called without required program name!\n");
		exit(-1);
	}
	r_opts.progname = strdup(argv[0]);
	if (!r_opts.progname) {
		fprintf(stderr, "%s:  Out of memory!\n", argv[0]);
		exit(-1);
	}
	base = basename(r_opts.progname);

	if (!strcmp(base, SETFILES)) {
		/*
		 * setfiles:
		 * Recursive descent,
		 * Does not expand paths via realpath,
		 * Try to track inode associations for conflict detection,
		 * Does not follow mounts (sets SELINUX_RESTORECON_XDEV),
		 * Validates all file contexts at init time.
		 */
		iamrestorecon = 0;
		r_opts.recurse = SELINUX_RESTORECON_RECURSE;
		r_opts.userealpath = 0; /* SELINUX_RESTORECON_REALPATH */
		r_opts.add_assoc = SELINUX_RESTORECON_ADD_ASSOC;
		/* FTS_PHYSICAL and FTS_NOCHDIR are always set by selinux_restorecon(3) */
		r_opts.xdev = SELINUX_RESTORECON_XDEV;
		r_opts.ignore_mounts = 0; /* SELINUX_RESTORECON_IGNORE_MOUNTS */
		ctx_validate = 1;
		opts = sopts;
	} else {
		/*
		 * restorecon:
		 * No recursive descent unless -r/-R,
		 * Expands paths via realpath,
		 * Do not try to track inode associations for conflict detection,
		 * Follows mounts,
		 * Does lazy validation of contexts upon use.
		 */
		if (strcmp(base, RESTORECON))
			fprintf(stderr, "Executed with unrecognized name (%s), defaulting to %s behavior.\n",
				base, RESTORECON);

		iamrestorecon = 1;
		r_opts.recurse = 0;
		r_opts.userealpath = SELINUX_RESTORECON_REALPATH;
		r_opts.add_assoc = 0;
		r_opts.xdev = 0;
		r_opts.ignore_mounts = 0;
		ctx_validate = 0;
		opts = ropts;

		/* restorecon only:  silent exit if no SELinux.
		 * Allows unconditional execution by scripts.
		 */
		if (is_selinux_enabled() <= 0)
			exit(0);
	}

	/* Process any options. */
	while ((opt = getopt(argc, argv, opts)) > 0) {
		switch (opt) {
		case 'c':
			{
				FILE *policystream;

				policyfile = optarg;

				policystream = fopen(policyfile, "r");
				if (!policystream) {
					fprintf(stderr,
						"Error opening %s: %s\n",
						policyfile, strerror(errno));
					exit(-1);
				}
				__fsetlocking(policystream,
					      FSETLOCKING_BYCALLER);

				if (sepol_set_policydb_from_file(policystream)
									< 0) {
					fprintf(stderr,
						"Error reading policy %s: %s\n",
						policyfile, strerror(errno));
					exit(-1);
				}
				fclose(policystream);

				ctx_validate = 1;
				break;
			}
		case 'e':
			if (lstat(optarg, &sb) < 0 && errno != EACCES) {
				fprintf(stderr, "Can't stat exclude path \"%s\", %s - ignoring.\n",
					optarg, strerror(errno));
				break;
			}
			add_exclude(optarg);
			break;
		case 'f':
			use_input_file = 1;
			input_filename = optarg;
			break;
		case 'd':
			r_opts.debug = 1;
			r_opts.log_matches =
					   SELINUX_RESTORECON_LOG_MATCHES;
			break;
		case 'i':
			r_opts.ignore_noent =
					   SELINUX_RESTORECON_IGNORE_NOENTRY;
			break;
		case 'I': /* Force label check by ignoring directory digest. */
			r_opts.ignore_digest =
					   SELINUX_RESTORECON_IGNORE_DIGEST;
			request_digest = 1;
			break;
		case 'D': /*
			   * Request file_contexts digest in selabel_open
			   * This will effectively enable usage of the
			   * security.restorecon_last extended attribute.
			   */
			request_digest = 1;
			break;
		case 'l':
			r_opts.syslog_changes =
					   SELINUX_RESTORECON_SYSLOG_CHANGES;
			break;
		case 'C':
			r_opts.count_errors = SELINUX_RESTORECON_COUNT_ERRORS;
			break;
		case 'E':
			r_opts.conflict_error =
					   SELINUX_RESTORECON_CONFLICT_ERROR;
			break;
		case 'F':
			r_opts.set_specctx =
					   SELINUX_RESTORECON_SET_SPECFILE_CTX;
			break;
		case 'U':
			r_opts.set_user_role =
					   SELINUX_RESTORECON_SET_USER_ROLE;
			break;
		case 'm':
			r_opts.ignore_mounts =
					   SELINUX_RESTORECON_IGNORE_MOUNTS;
			break;
		case 'n':
			r_opts.nochange = SELINUX_RESTORECON_NOCHANGE;
			break;
		case 'o': /* Deprecated */
			fprintf(stderr, "%s: -o option no longer supported\n",
				r_opts.progname);
			break;
		case 'q':
			/* Deprecated - Was only used to say whether print
			 * filespec_eval() params. Now uses verbose flag.
			 */
			break;
		case 'R':
		case 'r':
			if (iamrestorecon) {
				r_opts.recurse = SELINUX_RESTORECON_RECURSE;
				break;
			}

			if (lstat(optarg, &sb) < 0 && errno != EACCES) {
				fprintf(stderr,
					"Can't stat alt_root_path \"%s\", %s\n",
					optarg, strerror(errno));
				exit(-1);
			}

			if (r_opts.rootpath) {
				fprintf(stderr,
					"%s: only one -r can be specified\n",
					argv[0]);
				exit(-1);
			}
			set_rootpath(optarg);
			break;
		case 's':
			use_input_file = 1;
			input_filename = "-";
			r_opts.add_assoc = 0;
			break;
		case 'v':
			if (r_opts.progress) {
				fprintf(stderr,
					"Progress and Verbose mutually exclusive\n");
				usage(argv[0]);
			}
			r_opts.verbose = SELINUX_RESTORECON_VERBOSE;
			break;
		case 'p':
			if (r_opts.verbose) {
				fprintf(stderr,
					"Progress and Verbose mutually exclusive\n");
				usage(argv[0]);
			}
			r_opts.progress = SELINUX_RESTORECON_PROGRESS;
			break;
		case 'W':
			warn_no_match = 1; /* Print selabel_stats() */
			break;
		case '0':
			null_terminated = 1;
			break;
		case 'x':
			r_opts.xdev = SELINUX_RESTORECON_XDEV;
			break;
		case 'T':
			nthreads = strtoull(optarg, &endptr, 10);
			if (*optarg == '\0' || *endptr != '\0')
				usage(argv[0]);
			break;
		case 'A':
			r_opts.add_assoc = 0;
			break;
		case 'h':
		case '?':
			usage(argv[0]);
		}
	}

	for (i = optind; i < argc; i++) {
		if (!strcmp(argv[i], "/"))
			r_opts.mass_relabel = SELINUX_RESTORECON_MASS_RELABEL;
	}

	cb.func_log = log_callback;
	selinux_set_callback(SELINUX_CB_LOG, cb);

	if (!iamrestorecon) {
		if (policyfile) {
			if (optind > (argc - 1))
				usage(argv[0]);
		} else if (use_input_file) {
			if (optind != (argc - 1)) {
				/* Cannot mix with pathname arguments. */
				usage(argv[0]);
			}
		} else {
			if (optind > (argc - 2))
				usage(argv[0]);
		}

		/* Use our own invalid context checking function so that
		 * we can support either checking against the active policy or
		 * checking against a binary policy file.
		 */
		cb.func_validate = canoncon;
		selinux_set_callback(SELINUX_CB_VALIDATE, cb);

		if (stat(argv[optind], &sb) < 0) {
			perror(argv[optind]);
			exit(-1);
		}
		if (!S_ISREG(sb.st_mode)) {
			fprintf(stderr, "%s:  spec file %s is not a regular file.\n",
				argv[0], argv[optind]);
			exit(-1);
		}

		altpath = argv[optind];
		optind++;
	} else if (argc < 2)
		usage(argv[0]);

	/* Set selabel_open options. */
	r_opts.selabel_opt_validate = (ctx_validate ? (char *)1 : NULL);
	r_opts.selabel_opt_digest = (request_digest ? (char *)1 : NULL);
	r_opts.selabel_opt_path = altpath;

	restore_init(&r_opts);

	if (use_input_file) {
		FILE *f = stdin;
		ssize_t len;
		int delim;

		if (strcmp(input_filename, "-") != 0)
			f = fopen(input_filename, "r");

		if (f == NULL) {
			fprintf(stderr, "Unable to open %s: %s\n",
				input_filename,
				strerror(errno));
			usage(argv[0]);
		}
		__fsetlocking(f, FSETLOCKING_BYCALLER);

		delim = (null_terminated != 0) ? '\0' : '\n';
		while ((len = getdelim(&buf, &buf_len, delim, f)) > 0) {
			buf[len - 1] = 0;
			if (!strcmp(buf, "/"))
				r_opts.mass_relabel = SELINUX_RESTORECON_MASS_RELABEL;
			errors |= process_glob(buf, &r_opts, nthreads,
					       &skipped_errors) < 0;
		}
		if (strcmp(input_filename, "-") != 0)
			fclose(f);
	} else {
		for (i = optind; i < argc; i++)
			errors |= process_glob(argv[i], &r_opts, nthreads,
					       &skipped_errors) < 0;
	}

	if (r_opts.mass_relabel && !r_opts.nochange)
		audit_mass_relabel(errors);

	if (warn_no_match)
		selabel_stats(r_opts.hnd);

	selabel_close(r_opts.hnd);
	restore_finish();

	if (r_opts.progress)
		fprintf(stdout, "\n");

	exit(errors ? -1 : skipped_errors ? 1 : 0);
}
