#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <stdbool.h>
#include <sepol/sepol.h>
#include <selinux/label.h>
#include <selinux/restorecon.h>

static char *policyfile;

static char **exclude_list;
static int exclude_count;

static int validate_context(char **contextp)
{
	char *context = *contextp, *tmpcon;

	if (policyfile) {
		if (sepol_check_context(context) < 0) {
			fprintf(stderr, "Invalid context %s\n", context);
			exit(-1);
		}
	} else if (security_canonicalize_context_raw(context, &tmpcon) == 0) {
		free(context);
		*contextp = tmpcon;
	} else if (errno != ENOENT) {
		fprintf(stderr, "Validate context error: %s\n",
						    strerror(errno));
		exit(-1);
	}

	return 0;
}

static void usage(const char *progname)
{
	fprintf(stderr,
		"\nusage: %s [-FCnRrdei] [-v|-P] [-p policy] [-f specfile] "
		"pathname ...\n"
		"Where:\n\t"
		"-F  Set the label to that in specfile.\n\t"
		"    If not set then reset the \"type\" component of the "
		"label to that\n\t    in the specfile.\n\t"
		"-C  Check labels even if the stored SHA1 digest matches\n\t"
		"    the specfiles SHA1 digest.\n\t"
		"-n  Don't change any file labels (passive check).\n\t"
		"-R  Recursively change file and directory labels.\n\t"
		"-v  Show changes in file labels (-v and -P are mutually "
		" exclusive).\n\t"
		"-P  Show progress by printing \"*\" to stdout every 1000 files.\n\t"
		"-r  Use realpath(3) to convert pathnames to canonical form.\n\t"
		"-d  Prevent descending into directories that have a "
		"different\n\t    device number than the pathname from  which "
		"the descent began.\n\t"
		"-e  Exclude this file/directory (add multiple -e entries).\n\t"
		"-i  Do not set SELABEL_OPT_VALIDATE option in selabel_open(3)"
		" then call\n\t    selinux_restorecon_set_sehandle(3).\n\t"
		"-p  Optional binary policy file (also sets validate context "
		"option).\n\t"
		"-f  Optional file contexts file.\n\t"
		"pathname  One or more paths to relabel.\n\n",
		progname);
	exit(-1);
}

static void add_exclude(const char *directory)
{
	char **tmp_list;

	if (directory == NULL || directory[0] != '/') {
		fprintf(stderr, "Full path required for exclude: %s.\n",
			directory);
		exit(-1);
	}

	/* Add another two entries, one for directory, and the other to
	 * terminate the list */
	tmp_list = realloc(exclude_list, sizeof(char *) * (exclude_count + 2));
	if (!tmp_list) {
		fprintf(stderr, "ERROR: realloc failed.\n");
		exit(-1);
	}
	exclude_list = tmp_list;

	exclude_list[exclude_count] = strdup(directory);
	if (!exclude_list[exclude_count]) {
		fprintf(stderr, "ERROR: strdup failed.\n");
		exit(-1);
	}
	exclude_count++;
	exclude_list[exclude_count] = NULL;
}

int main(int argc, char **argv)
{
	int opt, i;
	unsigned int restorecon_flags = 0;
	char *path = NULL, *digest = NULL, *validate = NULL;
	FILE *policystream;
	bool ignore_digest = false, require_selinux = true;
	bool verbose = false, progress = false;

	struct selabel_handle *hnd = NULL;
	struct selinux_opt selabel_option[] = {
		{ SELABEL_OPT_PATH, path },
		{ SELABEL_OPT_DIGEST, digest },
		{ SELABEL_OPT_VALIDATE, validate }
	};

	if (argc < 2)
		usage(argv[0]);

	exclude_list = NULL;
	exclude_count = 0;

	while ((opt = getopt(argc, argv, "iFCnRvPrde:f:p:")) > 0) {
		switch (opt) {
		case 'F':
			restorecon_flags |=
					SELINUX_RESTORECON_SET_SPECFILE_CTX;
			break;
		case 'C':
			restorecon_flags |=
					SELINUX_RESTORECON_IGNORE_DIGEST;
			break;
		case 'n':
			restorecon_flags |= SELINUX_RESTORECON_NOCHANGE;
			break;
		case 'R':
			restorecon_flags |= SELINUX_RESTORECON_RECURSE;
			break;
		case 'v':
			if (progress) {
				fprintf(stderr,
					"Progress and Verbose are mutually exclusive\n");
				exit(-1);
			}
			verbose = true;
			restorecon_flags |=  SELINUX_RESTORECON_VERBOSE;
			break;
		case 'P':
			if (verbose) {
				fprintf(stderr,
					"Progress and Verbose are mutually exclusive\n");
				exit(-1);
			}
			progress = true;
			restorecon_flags |=  SELINUX_RESTORECON_PROGRESS;
			break;
		case 'r':
			restorecon_flags |= SELINUX_RESTORECON_REALPATH;
			break;
		case 'd':
			restorecon_flags |= SELINUX_RESTORECON_XDEV;
			break;
		case 'e':
			add_exclude(optarg);
			break;
		case 'p':
			policyfile = optarg;

			policystream = fopen(policyfile, "r");
			if (!policystream) {
				fprintf(stderr,
					"ERROR: opening %s: %s\n",
					policyfile, strerror(errno));
				exit(-1);
			}

			if (sepol_set_policydb_from_file(policystream) < 0) {
				fprintf(stderr,
					"ERROR: reading policy %s: %s\n",
					policyfile, strerror(errno));
				exit(-1);
			}
			fclose(policystream);

			selinux_set_callback(SELINUX_CB_VALIDATE,
				    (union selinux_callback)&validate_context);
			require_selinux = false;
			break;
		case 'f':
			path = optarg;
			break;
		case 'i':
			ignore_digest = true;
			break;
		default:
			usage(argv[0]);
		}
	}

	if (require_selinux && (is_selinux_enabled() <= 0)) {
		fprintf(stderr,
		    "SELinux must be enabled to perform this operation.\n");
		exit(-1);
	}

	if (optind >= argc) {
		fprintf(stderr, "No pathname specified\n");
		exit(-1);
	}

	/* If any of these set then do our own selabel_open and pass
	 * handle to selinux_restorecon */
	if (ignore_digest || path || policyfile) {
		if (path)
			selabel_option[0].value = path;
		else
			selabel_option[0].value = NULL;

		if (ignore_digest)
			selabel_option[1].value = NULL;
		else
			selabel_option[1].value = (char *)1;

		if (policyfile) /* Validate */
			selabel_option[2].value = (char *)1;
		else
			selabel_option[2].value = NULL;

		hnd = selabel_open(SELABEL_CTX_FILE, selabel_option, 3);
		if (!hnd) {
			switch (errno) {
			case EOVERFLOW:
				fprintf(stderr, "ERROR: Number of specfiles or"
				    " specfile buffer caused an overflow.\n");
				break;
			default:
				fprintf(stderr, "ERROR: selabel_open: %s\n",
							    strerror(errno));
			}
			exit(-1);
		}
		selinux_restorecon_set_sehandle(hnd);
	}

	if (exclude_list)
		selinux_restorecon_set_exclude_list
						 ((const char **)exclude_list);

	/* Call restorecon for each path in list */
	for (i = optind; i < argc; i++) {
		if (selinux_restorecon(argv[i], restorecon_flags) < 0) {
			fprintf(stderr, "ERROR: selinux_restorecon: %s\n",
					    strerror(errno));
			exit(-1);
		}
	}

	if (exclude_list) {
		for (i = 0; exclude_list[i]; i++)
			free(exclude_list[i]);
		free(exclude_list);
	}

	if (hnd)
		selabel_close(hnd);

	return 0;
}
