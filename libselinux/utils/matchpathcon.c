#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <selinux/selinux.h>
#include <limits.h>
#include <stdlib.h>


void usage(const char *progname)
{
	fprintf(stderr,
		"usage:  %s [-N] [-n] [-f file_contexts] [-p prefix] [-Vq] path...\n",
		progname);
	exit(1);
}

int printmatchpathcon(char *path, int header, int mode)
{
	char *buf;
	int rc = matchpathcon(path, mode, &buf);
	if (rc < 0) {
		if (errno == ENOENT) {
			buf=strdup("<<none>>");
		} else {
			fprintf(stderr, "matchpathcon(%s) failed: %s\n", path,
				strerror(errno));
			return 1;
		}
	}
	if (header)
		printf("%s\t%s\n", path, buf);
	else
		printf("%s\n", buf);

	freecon(buf);
	return 0;
}

/*
 * We do not want to resolve a symlink to a real path if it is the final
 * component of the name.  Thus we split the pathname on the last "/" and
 * determine a real path component of the first portion.  We then have to
 * copy the last part back on to get the final real path.  Wheww.
 */
static int symlink_realpath(char *name, char *resolved_path)
{
	char *last_component;
	char *tmp_path, *p;
	size_t len = 0;
	int rc = 0;

	tmp_path = strdup(name);
	if (!tmp_path) {
		fprintf(stderr, "symlink_realpath(%s) strdup() failed: %s\n",
			name, strerror(errno));
		rc = -1;
		goto out;
	}

	last_component = strrchr(tmp_path, '/');

	if (last_component == tmp_path) {
		last_component++;
		p = strcpy(resolved_path, "/");
	} else if (last_component) {
		*last_component = '\0';
		last_component++;
		p = realpath(tmp_path, resolved_path);
	} else {
		last_component = tmp_path;
		p = realpath("./", resolved_path);
	}

	if (!p) {
		fprintf(stderr, "symlink_realpath(%s) realpath() failed: %s\n",
			name, strerror(errno));
		rc = -1;
		goto out;
	}

	len = strlen(p);
	if (len + strlen(last_component) + 1 > PATH_MAX) {
		fprintf(stderr, "symlink_realpath(%s) failed: Filename too long \n",
			name);
		rc = -1;
		goto out;
	}

	resolved_path += len;
	strcpy(resolved_path, last_component);
out:
	free(tmp_path);
	return rc;
}

int main(int argc, char **argv)
{
	int i, init = 0;
	int header = 1, opt;
	int verify = 0;
	int notrans = 0;
	int error = 0;
	int quiet = 0;

	if (argc < 2)
		usage(argv[0]);

	while ((opt = getopt(argc, argv, "Nnf:p:Vq")) > 0) {
		switch (opt) {
		case 'n':
			header = 0;
			break;
		case 'V':
			verify = 1;
			break;
		case 'N':
			notrans = 1;
			set_matchpathcon_flags(MATCHPATHCON_NOTRANS);
			break;
		case 'f':
			if (init) {
				fprintf(stderr,
					"%s:  -f and -p are exclusive\n",
					argv[0]);
				exit(1);
			}
			init = 1;
			if (matchpathcon_init(optarg)) {
				fprintf(stderr,
					"Error while processing %s:  %s\n",
					optarg,
					errno ? strerror(errno) : "invalid");
				exit(1);
			}
			break;
		case 'p':
			if (init) {
				fprintf(stderr,
					"%s:  -f and -p are exclusive\n",
					argv[0]);
				exit(1);
			}
			init = 1;
			if (matchpathcon_init_prefix(NULL, optarg)) {
				fprintf(stderr,
					"Error while processing %s:  %s\n",
					optarg,
					errno ? strerror(errno) : "invalid");
				exit(1);
			}
			break;
		case 'q':
			quiet = 1;
			break;
		default:
			usage(argv[0]);
		}
	}
	for (i = optind; i < argc; i++) {
		int rc, mode = 0;
		struct stat buf;
		char *p, *path = argv[i];
		char stackpath[PATH_MAX + 1];
		int len = strlen(path);
		if (len > 1  && path[len - 1 ] == '/')
			path[len - 1 ] = '\0';

		if (lstat(path, &buf) == 0)
			mode = buf.st_mode;

		if (S_ISLNK(mode)) {
			rc = symlink_realpath(path, stackpath);
			if (!rc)
				path = stackpath;
		} else {
			p = realpath(path, stackpath);
			if (p)
				path = p;
		}

		if (verify) {
			rc = selinux_file_context_verify(path, mode);

			if (quiet) {
				if (rc)
					continue;
				else
					exit(1);
			}

			if (rc) {
				printf("%s verified.\n", path);
			} else {
				security_context_t con;
				int rc;
				error = 1;
				if (notrans)
					rc = lgetfilecon_raw(path, &con);
				else
					rc = lgetfilecon(path, &con);

				if (rc >= 0) {
					printf("%s has context %s, should be ",
					       path, con);
					printmatchpathcon(path, 0, mode);
					freecon(con);
				} else {
					printf
					    ("actual context unknown: %s, should be ",
					     strerror(errno));
					printmatchpathcon(path, 0, mode);
				}
			}
		} else {
			error |= printmatchpathcon(path, header, mode);
		}
	}
	matchpathcon_fini();
	return error;
}
