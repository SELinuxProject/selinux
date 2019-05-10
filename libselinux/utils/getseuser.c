#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <selinux/selinux.h>
#include <selinux/get_context_list.h>

int main(int argc, char **argv)
{
	char *seuser = NULL, *level = NULL;
	char **contextlist;
	int rc, n, i;

	if (argc != 3) {
		fprintf(stderr, "usage:  %s linuxuser fromcon\n", argv[0]);
		exit(1);
	}

	rc = getseuserbyname(argv[1], &seuser, &level);
	if (rc) {
		fprintf(stderr, "getseuserbyname failed:  %s\n",
			strerror(errno));
		exit(2);
	}
	printf("seuser:  %s, level %s\n", seuser, level);
	n = get_ordered_context_list_with_level(seuser, level, argv[2],
						&contextlist);
	if (n <= 0) {
		fprintf(stderr,
			"get_ordered_context_list_with_level failed:  %s\n",
			strerror(errno));
		exit(3);
	}
	free(seuser);
	free(level);
	for (i = 0; i < n; i++)
		printf("Context %d\t%s\n", i, contextlist[i]);
	freeconary(contextlist);
	exit(EXIT_SUCCESS);
}
