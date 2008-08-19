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

int security_compute_av_raw(security_context_t scon,
			    security_context_t tcon,
			    security_class_t tclass,
			    access_vector_t requested, struct av_decision *avd)
{
	char path[PATH_MAX];
	char *buf;
	size_t len;
	int fd, ret;

	if (!selinux_mnt) {
		errno = ENOENT;
		return -1;
	}

	snprintf(path, sizeof path, "%s/access", selinux_mnt);
	fd = open(path, O_RDWR);
	if (fd < 0)
		return -1;

	len = selinux_page_size;
	buf = malloc(len);
	if (!buf) {
		ret = -1;
		goto out;
	}

	snprintf(buf, len, "%s %s %hu %x", scon, tcon, tclass, requested);

	ret = write(fd, buf, strlen(buf));
	if (ret < 0)
		goto out2;

	memset(buf, 0, len);
	ret = read(fd, buf, len - 1);
	if (ret < 0)
		goto out2;

	if (sscanf(buf, "%x %x %x %x %u", &avd->allowed,
		   &avd->decided, &avd->auditallow, &avd->auditdeny,
		   &avd->seqno) != 5) {
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

hidden_def(security_compute_av_raw)

int security_compute_av(security_context_t scon,
			security_context_t tcon,
			security_class_t tclass,
			access_vector_t requested, struct av_decision *avd)
{
	int ret;
	security_context_t rscon = scon;
	security_context_t rtcon = tcon;

	if (selinux_trans_to_raw_context(scon, &rscon))
		return -1;
	if (selinux_trans_to_raw_context(tcon, &rtcon)) {
		freecon(rscon);
		return -1;
	}

	ret = security_compute_av_raw(rscon, rtcon, tclass, requested, avd);

	freecon(rscon);
	freecon(rtcon);

	return ret;
}

hidden_def(security_compute_av)
