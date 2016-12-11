#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pwd.h>
#include <limits.h>
#include "selinux_internal.h"
#include "context_internal.h"

static int get_customizable_type_list(char *** retlist)
{
	FILE *fp;
	char *buf;
	unsigned int ctr = 0, i;
	char **list = NULL;

	fp = fopen(selinux_customizable_types_path(), "re");
	if (!fp)
		return -1;

	buf = malloc(selinux_page_size);
	if (!buf) {
		fclose(fp);
		return -1;
	}
	while (fgets_unlocked(buf, selinux_page_size, fp) && ctr < UINT_MAX) {
		ctr++;
	}
	rewind(fp);
	if (ctr) {
		list =
		    (char **) calloc(sizeof(char *),
						  ctr + 1);
		if (list) {
			i = 0;
			while (fgets_unlocked(buf, selinux_page_size, fp)
			       && i < ctr) {
				buf[strlen(buf) - 1] = 0;
				list[i] = (char *) strdup(buf);
				if (!list[i]) {
					unsigned int j;
					for (j = 0; j < i; j++)
						free(list[j]);
					free(list);
					list = NULL;
					break;
				}
				i++;
			}
		}
	}
	fclose(fp);
	free(buf);
	if (!list)
		return -1;
	*retlist = list;
	return 0;
}

static char **customizable_list = NULL;

int is_context_customizable(const char * scontext)
{
	int i;
	const char *type;
	context_t c;

	if (!customizable_list) {
		if (get_customizable_type_list(&customizable_list) != 0)
			return -1;
	}

	c = context_new(scontext);
	if (!c)
		return -1;

	type = context_type_get(c);
	if (!type) {
		context_free(c);
		return -1;
	}

	for (i = 0; customizable_list[i]; i++) {
		if (strcmp(customizable_list[i], type) == 0) {
			context_free(c);
			return 1;
		}
	}
	context_free(c);
	return 0;
}
