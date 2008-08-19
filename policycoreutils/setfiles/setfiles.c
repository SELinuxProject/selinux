/* 
 * setfiles
 *
 * AUTHOR:  Stephen Smalley <sds@epoch.ncsc.mil>
 * This program was derived in part from the setfiles.pl script
 * developed by Secure Computing Corporation.
 *
 * PURPOSE:
 * This program reads a set of file security context specifications
 * based on pathname regular expressions and labels files
 * accordingly, traversing a set of file systems specified by
 * the user.  The program does not cross file system boundaries.
 *
 * USAGE:
 * setfiles [-dnpqsvW] [-e directory ] [-c policy] [-o filename ] spec_file pathname...
 * 
 * -e   Specify directory to exclude
 * -F	Force reset of context to match file_context for customizable files
 * -c   Verify the specification file using a binary policy
 * -d   Show what specification matched each file.
 * -l   Log changes in files labels to syslog.
 * -n	Do not change any file labels.
 * -p   Show progress.  Prints * for every 1000 files
 * -q   Be quiet (suppress non-error output).
 * -r   Use an alternate root path
 * -s   Use stdin for a list of files instead of searching a partition.
 * -v	Show changes in file labels.  
 * -W   Warn about entries that have no matching file.
 * -o filename write out file names with wrong context.
 *
 * spec_file	The specification file.
 * pathname...	The file systems to label (omit if using -s).	
 *
 * EXAMPLE USAGE:
 * ./setfiles -v file_contexts `mount | awk '/ext3/{print $3}'`
 *
 * SPECIFICATION FILE:
 * Each specification has the form:
 *       regexp [ -type ] ( context | <<none>> )
 *
 * By default, the regexp is an anchored match on both ends (i.e. a 
 * caret (^) is prepended and a dollar sign ($) is appended automatically).
 * This default may be overridden by using .* at the beginning and/or
 * end of the regular expression.  
 *
 * The optional type field specifies the file type as shown in the mode
 * field by ls, e.g. use -d to match only directories or -- to match only
 * regular files.
 * 
 * The value of <<none> may be used to indicate that matching files
 * should not be relabeled.
 *
 * The last matching specification is used.
 *
 * If there are multiple hard links to a file that match 
 * different specifications and those specifications indicate
 * different security contexts, then a warning is displayed
 * but the file is still labeled based on the last matching
 * specification other than <<none>>.
 */

#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <regex.h>
#include <sys/vfs.h>
#define __USE_XOPEN_EXTENDED 1	/* nftw */
#include <ftw.h>
#include <limits.h>
#include <sepol/sepol.h>
#include <selinux/selinux.h>
#include <syslog.h>
#include <libgen.h>
#ifdef USE_AUDIT
#include <libaudit.h>

#ifndef AUDIT_FS_RELABEL
#define AUDIT_FS_RELABEL 2309
#endif
#endif

static int add_assoc = 1;
static FILE *outfile = NULL;
static int force = 0;
#define STAT_BLOCK_SIZE 1
static int pipe_fds[2] = { -1, -1 };
static int progress = 0;
static unsigned long long count = 0;

#define MAX_EXCLUDES 100
static int excludeCtr = 0;
struct edir {
	char *directory;
	size_t size;
};
static struct edir excludeArray[MAX_EXCLUDES];

/*
 * Command-line options.
 */
static char *policyfile = NULL;
static int debug = 0;
static int change = 1;
static int quiet = 0;
static int use_stdin = 0;
static int verbose = 0;
static int logging = 0;
static int warn_no_match = 0;
static char *rootpath = NULL;
static int rootpathlen = 0;

static char *progname;

static void
#ifdef __GNUC__
    __attribute__ ((format(printf, 1, 2)))
#endif
    qprintf(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	if (!quiet)
		vfprintf(stdout, fmt, ap);
	va_end(ap);
}

static int add_exclude(const char *directory)
{
	struct stat sb;
	if (directory == NULL || directory[0] != '/') {
		fprintf(stderr, "Full path required for exclude: %s.\n",
			directory);
		return 1;
	}
	if (lstat(directory, &sb)) {
		fprintf(stderr, "Directory \"%s\" not found, ignoring.\n",
			directory);
		return 0;
	}
	if ((sb.st_mode & S_IFDIR) == 0) {
		fprintf(stderr,
			"\"%s\" is not a Directory: mode %o, ignoring\n",
			directory, sb.st_mode);
		return 0;
	}

	if (excludeCtr == MAX_EXCLUDES) {
		fprintf(stderr, "Maximum excludes %d exceeded.\n",
			MAX_EXCLUDES);
		return 1;
	}

	excludeArray[excludeCtr].directory = strdup(directory);
	if (!excludeArray[excludeCtr].directory) {
		fprintf(stderr, "Out of memory.\n");
		return 1;
	}
	excludeArray[excludeCtr++].size = strlen(directory);

	return 0;
}

static int exclude(const char *file)
{
	int i = 0;
	for (i = 0; i < excludeCtr; i++) {
		if (strncmp
		    (file, excludeArray[i].directory,
		     excludeArray[i].size) == 0) {
			if (file[excludeArray[i].size] == 0
			    || file[excludeArray[i].size] == '/') {
				return 1;
			}
		}
	}
	return 0;
}

int match(const char *name, struct stat *sb, char **con)
{
	int ret;
	const char *fullname = name;

	/* fullname will be the real file that gets labeled
	 * name will be what is matched in the policy */
	if (NULL != rootpath) {
		if (0 != strncmp(rootpath, name, rootpathlen)) {
			fprintf(stderr, "%s:  %s is not located in %s\n",
				progname, name, rootpath);
			return -1;
		}
		name += rootpathlen;
	}

	if (excludeCtr > 0) {
		if (exclude(fullname)) {
			return -1;
		}
	}
	ret = lstat(fullname, sb);
	if (ret) {
		fprintf(stderr, "%s:  unable to stat file %s\n", progname,
			fullname);
		return -1;
	}

	if (rootpath != NULL && name[0] == '\0')
		/* this is actually the root dir of the alt root */
		return matchpathcon_index("/", sb->st_mode, con);
	else
		return matchpathcon_index(name, sb->st_mode, con);
}

void usage(const char *const name)
{
	fprintf(stderr,
		"usage:  %s [-dnpqvW] [-o filename] [-r alt_root_path ] spec_file pathname...\n"
		"usage:  %s -c policyfile spec_file\n"
		"usage:  %s -s [-dnqvW] [-o filename ] spec_file\n", name, name,
		name);
	exit(1);
}

static int nerr = 0;

void inc_err()
{
	nerr++;
	if (nerr > 9 && !debug) {
		fprintf(stderr, "Exiting after 10 errors.\n");
		exit(1);
	}
}

/* Compare two contexts to see if their differences are "significant",
 * or whether the only difference is in the user. */
static int only_changed_user(const char *a, const char *b)
{
	char *rest_a, *rest_b;	/* Rest of the context after the user */
	if (force)
		return 0;
	if (!a || !b)
		return 0;
	rest_a = strchr(a, ':');
	rest_b = strchr(b, ':');
	if (!rest_a || !rest_b)
		return 0;
	return (strcmp(rest_a, rest_b) == 0);
}

/*
 * Apply the last matching specification to a file.
 * This function is called by nftw on each file during
 * the directory traversal.
 */
static int apply_spec(const char *file,
		      const struct stat *sb_unused __attribute__ ((unused)),
		      int flag, struct FTW *s_unused __attribute__ ((unused)))
{
	const char *my_file;
	struct stat my_sb;
	int i, j, ret;
	char *context, *newcon;
	int user_only_changed = 0;
	char buf[STAT_BLOCK_SIZE];
	if (pipe_fds[0] != -1
	    && read(pipe_fds[0], buf, STAT_BLOCK_SIZE) != STAT_BLOCK_SIZE) {
		fprintf(stderr, "Read error on pipe.\n");
		pipe_fds[0] = -1;
	}

	/* Skip the extra slash at the beginning, if present. */
	if (file[0] == '/' && file[1] == '/')
		my_file = &file[1];
	else
		my_file = file;

	if (flag == FTW_DNR) {
		fprintf(stderr, "%s:  unable to read directory %s\n",
			progname, my_file);
		return 0;
	}

	i = match(my_file, &my_sb, &newcon);
	if (i < 0)
		/* No matching specification. */
		return 0;

	if (progress) {
		count++;
		if (count % 80000 == 0) {
			fprintf(stdout, "\n");
			fflush(stdout);
		}
		if (count % 1000 == 0) {
			fprintf(stdout, "*");
			fflush(stdout);
		}
	}

	/*
	 * Try to add an association between this inode and
	 * this specification.  If there is already an association
	 * for this inode and it conflicts with this specification,
	 * then use the last matching specification.
	 */
	if (add_assoc) {
		j = matchpathcon_filespec_add(my_sb.st_ino, i, my_file);
		if (j < 0)
			goto err;

		if (j != i) {
			/* There was already an association and it took precedence. */
			goto out;
		}
	}

	if (debug) {
		printf("%s:  %s matched by %s\n", progname, my_file, newcon);
	}

	/* Get the current context of the file. */
	ret = lgetfilecon_raw(my_file, &context);
	if (ret < 0) {
		if (errno == ENODATA) {
			context = NULL;
		} else {
			perror(my_file);
			fprintf(stderr,
				"%s:  unable to obtain attribute for file %s\n",
				progname, my_file);
			goto err;
		}
		user_only_changed = 0;
	} else
		user_only_changed = only_changed_user(context, newcon);

	/*
	 * Do not relabel the file if the matching specification is 
	 * <<none>> or the file is already labeled according to the 
	 * specification.
	 */
	if ((strcmp(newcon, "<<none>>") == 0) ||
	    (context && (strcmp(context, newcon) == 0))) {
		freecon(context);
		goto out;
	}

	if (!force && context && (is_context_customizable(context) > 0)) {
		if (verbose > 1) {
			fprintf(stderr,
				"%s: %s not reset customized by admin to %s\n",
				progname, my_file, context);
		}
		freecon(context);
		goto out;
	}

	if (verbose) {
		/* If we're just doing "-v", trim out any relabels where
		 * the user has changed but the role and type are the
		 * same.  For "-vv", emit everything. */
		if (verbose > 1 || !user_only_changed) {
			if (context)
				printf("%s:  relabeling %s from %s to %s\n",
				       progname, my_file, context, newcon);
			else
				printf("%s:  labeling %s to %s\n", progname,
				       my_file, newcon);
		}
	}

	if (logging && !user_only_changed) {
		if (context)
			syslog(LOG_INFO, "relabeling %s from %s to %s\n",
			       my_file, context, newcon);
		else
			syslog(LOG_INFO, "labeling %s to %s\n",
			       my_file, newcon);
	}

	if (outfile && !user_only_changed)
		fprintf(outfile, "%s\n", my_file);

	if (context)
		freecon(context);

	/*
	 * Do not relabel the file if -n was used.
	 */
	if (!change || user_only_changed)
		goto out;

	/*
	 * Relabel the file to the specified context.
	 */
	ret = lsetfilecon(my_file, newcon);
	if (ret) {
		perror(my_file);
		fprintf(stderr, "%s:  unable to relabel %s to %s\n",
			progname, my_file, newcon);
		goto out;
	}
      out:
	freecon(newcon);
	return 0;
      err:
	freecon(newcon);
	return -1;
}

void set_rootpath(const char *arg)
{
	int len;

	rootpath = strdup(arg);
	if (NULL == rootpath) {
		fprintf(stderr, "%s:  insufficient memory for rootpath\n",
			progname);
		exit(1);
	}

	/* trim trailing /, if present */
	len = strlen(rootpath);
	while (len && ('/' == rootpath[len - 1]))
		rootpath[--len] = 0;
	rootpathlen = len;
}

int canoncon(const char *path, unsigned lineno, char **contextp)
{
	char *context = *contextp, *tmpcon;
	int valid = 1;

	if (policyfile) {
		valid = (sepol_check_context(context) >= 0);
	} else if (security_canonicalize_context_raw(context, &tmpcon) < 0) {
		if (errno != ENOENT) {
			valid = 0;
			inc_err();
		}
	} else {
		free(context);
		*contextp = tmpcon;
	}

	if (!valid) {
		fprintf(stderr, "%s:  line %u has invalid context %s\n",
			path, lineno, context);

		/* Exit immediately if we're in checking mode. */
		if (policyfile)
			exit(1);
	}

	return !valid;
}

static int pre_stat(const char *file_unused __attribute__ ((unused)),
		    const struct stat *sb_unused __attribute__ ((unused)),
		    int flag_unused __attribute__ ((unused)),
		    struct FTW *s_unused __attribute__ ((unused)))
{
	char buf[STAT_BLOCK_SIZE];
	if (write(pipe_fds[1], buf, STAT_BLOCK_SIZE) != STAT_BLOCK_SIZE) {
		fprintf(stderr, "Error writing to stat pipe, child exiting.\n");
		exit(1);
	}
	return 0;
}

#ifndef USE_AUDIT
static void maybe_audit_mass_relabel(int done_root __attribute__ ((unused)),
				     int err __attribute__ ((unused)))
{
#else
static void maybe_audit_mass_relabel(int done_root, int errs)
{
	int audit_fd = -1;
	int rc = 0;

	if (!done_root)		/* only audit a forced full relabel */
		return;

	audit_fd = audit_open();

	if (audit_fd < 0) {
		fprintf(stderr, "Error connecting to audit system.\n");
		exit(-1);
	}

	rc = audit_log_user_message(audit_fd, AUDIT_FS_RELABEL,
				    "op=mass relabel", NULL, NULL, NULL, !errs);
	if (rc <= 0) {
		fprintf(stderr, "Error sending audit message: %s.\n",
			strerror(errno));
		/* exit(-1); -- don't exit atm. as fix for eff_cap isn't in most kernels */
	}
	audit_close(audit_fd);
#endif
}

int main(int argc, char **argv)
{
	struct stat sb;
	int opt, rc, i;
	int done_root = 0;	/* have we processed the / directory as an arg */

	memset(excludeArray, 0, sizeof(excludeArray));

	/* Validate all file contexts during matchpathcon_init. */
	set_matchpathcon_flags(MATCHPATHCON_VALIDATE | MATCHPATHCON_NOTRANS);

	/* Process any options. */
	while ((opt = getopt(argc, argv, "Fc:dlnpqrsvWe:o:")) > 0) {
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
					exit(1);
				}
				__fsetlocking(policystream,
					      FSETLOCKING_BYCALLER);

				if (sepol_set_policydb_from_file(policystream) <
				    0) {
					fprintf(stderr,
						"Error reading policy %s: %s\n",
						policyfile, strerror(errno));
					exit(1);
				}
				fclose(policystream);

				/* Only process the specified file_contexts file, not
				   any .homedirs or .local files, and do not perform
				   context translations. */
				set_matchpathcon_flags(MATCHPATHCON_BASEONLY |
						       MATCHPATHCON_NOTRANS |
						       MATCHPATHCON_VALIDATE);

				break;
			}
		case 'e':
			if (add_exclude(optarg))
				exit(1);
			break;

		case 'd':
			debug = 1;
			break;
		case 'l':
			logging = 1;
			break;
		case 'F':
			force = 1;
			break;
		case 'n':
			change = 0;
			break;
		case 'o':
			outfile = fopen(optarg, "w");
			if (!outfile) {
				fprintf(stderr, "Error opening %s: %s\n",
					optarg, strerror(errno));

				usage(argv[0]);
			}
			__fsetlocking(outfile, FSETLOCKING_BYCALLER);
			break;
		case 'q':
			quiet = 1;
			break;
		case 'r':
			if (optind + 1 >= argc) {
				fprintf(stderr, "usage:  %s -r rootpath\n",
					argv[0]);
				exit(1);
			}
			if (NULL != rootpath) {
				fprintf(stderr,
					"%s: only one -r can be specified\n",
					argv[0]);
				exit(1);
			}
			set_rootpath(argv[optind++]);
			break;
		case 's':
			use_stdin = 1;
			add_assoc = 0;
			break;
		case 'v':
			if (progress) {
				fprintf(stderr,
					"Progress and Verbose mutually exclusive\n");
				exit(1);
			}
			verbose++;
			break;
		case 'p':
			if (verbose) {
				fprintf(stderr,
					"Progress and Verbose mutually exclusive\n");
				usage(argv[0]);
			}
			progress = 1;
			break;
		case 'W':
			warn_no_match = 1;
			break;
		case '?':
			usage(argv[0]);
		}
	}

	if (policyfile) {
		if (optind != (argc - 1))
			usage(argv[0]);
	} else if (use_stdin) {
		if (optind != (argc - 1)) {
			/* Cannot mix with pathname arguments. */
			usage(argv[0]);
		}
	} else {
		if (optind > (argc - 2))
			usage(argv[0]);
	}

	/* Use our own invalid context checking function so that
	   we can support either checking against the active policy or
	   checking against a binary policy file. */
	set_matchpathcon_canoncon(&canoncon);

	if (stat(argv[optind], &sb) < 0) {
		perror(argv[optind]);
		exit(1);
	}
	if (!S_ISREG(sb.st_mode)) {
		fprintf(stderr, "%s:  spec file %s is not a regular file.\n",
			argv[0], argv[optind]);
		exit(1);
	}

	/* Load the file contexts configuration and check it. */
	rc = matchpathcon_init(argv[optind]);
	if (rc < 0) {
		perror(argv[optind]);
		exit(1);
	}

	optind++;

	if (nerr)
		exit(1);

	/*
	 * Apply the specifications to the file systems.
	 */
	progname = argv[0];
	if (use_stdin) {
		char buf[PATH_MAX];
		while (fgets(buf, sizeof(buf), stdin)) {
			struct stat sb;
			strtok(buf, "\n");
			if (buf[0] != '\n') {
				if (lstat(buf, &sb))
					fprintf(stderr,
						"File \"%s\" not found.\n",
						buf);
				else {
					int flag;
					switch (sb.st_mode) {
					case S_IFDIR:
						flag = FTW_D;
						break;
					case S_IFLNK:
						flag = FTW_SL;
						break;
					default:
						flag = FTW_F;
					}
					apply_spec(buf, &sb, flag, NULL);
				}
			}
		}
	} else
		for (; optind < argc; optind++) {
			done_root |= !strcmp(argv[optind], "/");

			if (NULL != rootpath) {
				qprintf
				    ("%s:  labeling files, pretending %s is /\n",
				     argv[0], rootpath);
			}

			qprintf("%s:  labeling files under %s\n", argv[0],
				argv[optind]);

			int rc;
			if (pipe(pipe_fds) == -1)
				rc = -1;
			else
				rc = fork();
			if (rc == 0) {
				close(pipe_fds[0]);
				nftw(argv[optind], pre_stat, 1024, FTW_PHYS);
				exit(1);
			}
			if (rc > 0)
				close(pipe_fds[1]);
			if (rc == -1 || rc > 0) {

				/* Walk the file tree, calling apply_spec on each file. */
				if (nftw
				    (argv[optind], apply_spec, 1024,
				     FTW_PHYS | FTW_MOUNT)) {
					fprintf(stderr,
						"%s:  error while labeling files under %s\n",
						argv[0], argv[optind]);
					maybe_audit_mass_relabel(done_root, 1);
					exit(1);
				}
			}

			/*
			 * Evaluate the association hash table distribution for the
			 * directory tree just traversed.
			 */
			set_matchpathcon_printf(&qprintf);
			matchpathcon_filespec_eval();
			set_matchpathcon_printf(NULL);

			/* Reset the association hash table for the next directory tree. */
			matchpathcon_filespec_destroy();
		}

	maybe_audit_mass_relabel(done_root, 0);

	if (warn_no_match)
		matchpathcon_checkmatches(argv[0]);

	if (outfile)
		fclose(outfile);

	for (i = 0; i < excludeCtr; i++) {
		free(excludeArray[i].directory);
	}

	qprintf("%s:  Done.\n", argv[0]);

	exit(0);
}
