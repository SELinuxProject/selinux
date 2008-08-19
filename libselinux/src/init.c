#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>

#include "dso.h"
#include "policy.h"
#include "selinux_internal.h"
#include "setrans_internal.h"

char *selinux_mnt = NULL;
int selinux_page_size = 0;

static void init_selinuxmnt(void)
{
	char *buf, *bufp, *p;
	size_t size;
	FILE *fp;

	if (selinux_mnt)
		return;

	fp = fopen("/proc/mounts", "r");
	if (!fp)
		return;

	size = selinux_page_size;

	buf = malloc(size);
	if (!buf)
		goto out;

	memset(buf, 0, size);

	while ((bufp = fgets_unlocked(buf, size, fp))) {
		char *tmp;
		p = strchr(buf, ' ');
		if (!p)
			goto out2;
		p++;
		tmp = strchr(p, ' ');
		if (!tmp)
			goto out2;
		if (!strncmp(tmp + 1, "selinuxfs ", 10)) {
			*tmp = '\0';
			break;
		}
	}

	if (!bufp)
		goto out2;

	selinux_mnt = strdup(p);

      out2:
	free(buf);
      out:
	fclose(fp);
	return;

}

static void fini_selinuxmnt(void)
{
	free(selinux_mnt);
	selinux_mnt = NULL;
}

void set_selinuxmnt(char *mnt)
{
	selinux_mnt = strdup(mnt);
}

hidden_def(set_selinuxmnt)

static void init_lib(void) __attribute__ ((constructor));
static void init_lib(void)
{
	selinux_page_size = sysconf(_SC_PAGE_SIZE);
	init_selinuxmnt();
	init_context_translations();
}

static void fini_lib(void) __attribute__ ((destructor));
static void fini_lib(void)
{
	fini_selinuxmnt();
	fini_context_translations();
}
