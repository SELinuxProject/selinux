#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "selinux_internal.h"
#include "policy.h"
#include <limits.h>

#define SELINUX_INITCON_DIR "/initial_contexts/"

int security_get_initial_context_raw(const char * name, char ** con)
{
	char path[PATH_MAX];
	char *buf;
	size_t size;
	int fd, ret;

	if (!selinux_mnt) {
		errno = ENOENT;
		return -1;
	}

	snprintf(path, sizeof path, "%s%s%s", 
		 selinux_mnt, SELINUX_INITCON_DIR, name);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;

	size = selinux_page_size;
	buf = malloc(size);
	if (!buf) {
		ret = -1;
		goto out;
	}
	memset(buf, 0, size);
	ret = read(fd, buf, size - 1);
	if (ret < 0)
		goto out2;

	*con = strdup(buf);
	if (!(*con)) {
		ret = -1;
		goto out2;
	}
	ret = 0;
      out2:
	free(buf);
      out:
	close(fd);
	return ret;
}

hidden_def(security_get_initial_context_raw)

int security_get_initial_context(const char * name, char ** con)
{
	int ret;
	char * rcon;

	ret = security_get_initial_context_raw(name, &rcon);
	if (!ret) {
		ret = selinux_raw_to_trans_context(rcon, con);
		freecon(rcon);
	}

	return ret;
}

hidden_def(security_get_initial_context)
