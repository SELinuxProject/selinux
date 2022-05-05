#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <selinux/selinux.h>
#include <selinux/get_context_list.h>

static __attribute__ ((__noreturn__)) void usage(const char *name, const char *detail, int rc)
{
	fprintf(stderr, "usage:  %s [-l level] [-s service] user [fromcon]\n", name);
	if (detail)
		fprintf(stderr, "%s:  %s\n", name, detail);
	exit(rc);
}

int main(int argc, char **argv)
{
	char * usercon = NULL, *cur_context = NULL;
	char *user = NULL, *level = NULL, *role=NULL, *seuser=NULL, *dlevel=NULL;
	char *service = NULL;
	int ret, opt;
	int verbose = 0;

	while ((opt = getopt(argc, argv, "l:r:s:v")) > 0) {
		switch (opt) {
		case 'l':
			free(level);
			level = strdup(optarg);
			break;
		case 'r':
			free(role);
			role = strdup(optarg);
			break;
		case 's':
			free(service);
			service = strdup(optarg);
			break;
		case 'v':
			verbose = 1;
			break;
		default:
			usage(argv[0], "invalid option", 1);
		}
	}

	if (((argc - optind) < 1) || ((argc - optind) > 2))
		usage(argv[0], "invalid number of arguments", 2);

	/* If selinux isn't available, bail out. */
	if (!is_selinux_enabled()) {
		fprintf(stderr,
			"%s may be used only on a SELinux kernel.\n", argv[0]);
		return 1;
	}

	user = argv[optind];

	/* If a context wasn't passed, use the current context. */
	if (((argc - optind) < 2)) {
		if (getcon(&cur_context) < 0) {
			fprintf(stderr, "Couldn't get current context:  %s\n", strerror(errno));
			return 2;
		}
	} else
		cur_context = argv[optind + 1];

	if (security_check_context(cur_context)) {
		fprintf(stderr, "%s:  invalid from context '%s'\n", argv[0], cur_context);
		return 3;
	}

	if ((ret = getseuser(user, service, &seuser, &dlevel)) == 0) {
		if (! level) level=dlevel;
		if (role != NULL && role[0]) 
			ret=get_default_context_with_rolelevel(seuser, role, level,cur_context,&usercon);
		else
			ret=get_default_context_with_level(seuser, level, cur_context,&usercon);
	}
	if (ret < 0)
		perror(argv[0]);
	else {
		if (verbose) {
			printf("%s: %s from %s %s %s %s -> %s\n", argv[0], user, cur_context, seuser, role, level, usercon);
		} else {
			printf("%s\n", usercon);
		}
	}

	free(role);
	free(seuser);
	if (level != dlevel) free(level);
	free(dlevel);
	free(usercon);

	return ret >= 0;
}
