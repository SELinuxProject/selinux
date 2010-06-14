#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include "selinux_internal.h"
#include "policy.h"

static pid_t gettid(void)
{
	return syscall(__NR_gettid);
}

static int getprocattrcon_raw(security_context_t * context,
			      pid_t pid, const char *attr)
{
	char *path, *buf;
	size_t size;
	int fd, rc;
	ssize_t ret;
	pid_t tid;
	int errno_hold;

	if (pid > 0)
		rc = asprintf(&path, "/proc/%d/attr/%s", pid, attr);
	else {
		tid = gettid();
		rc = asprintf(&path, "/proc/self/task/%d/attr/%s", tid, attr);
	}
	if (rc < 0)
		return -1;

	fd = open(path, O_RDONLY);
	free(path);
	if (fd < 0)
		return -1;

	size = selinux_page_size;
	buf = malloc(size);
	if (!buf) {
		ret = -1;
		goto out;
	}
	memset(buf, 0, size);

	do {
		ret = read(fd, buf, size - 1);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0)
		goto out2;

	if (ret == 0) {
		*context = NULL;
		goto out2;
	}

	*context = strdup(buf);
	if (!(*context)) {
		ret = -1;
		goto out2;
	}
	ret = 0;
      out2:
	free(buf);
      out:
	errno_hold = errno;
	close(fd);
	errno = errno_hold;
	return ret;
}

static int getprocattrcon(security_context_t * context,
			  pid_t pid, const char *attr)
{
	int ret;
	security_context_t rcontext;

	ret = getprocattrcon_raw(&rcontext, pid, attr);

	if (!ret) {
		ret = selinux_raw_to_trans_context(rcontext, context);
		freecon(rcontext);
	}

	return ret;
}

static int setprocattrcon_raw(security_context_t context,
			      pid_t pid, const char *attr)
{
	char *path;
	int fd, rc;
	pid_t tid;
	ssize_t ret;
	int errno_hold;

	if (pid > 0)
		rc = asprintf(&path, "/proc/%d/attr/%s", pid, attr);
	else {
		tid = gettid();
		rc = asprintf(&path, "/proc/self/task/%d/attr/%s", tid, attr);
	}
	if (rc < 0)
		return -1;

	fd = open(path, O_RDWR);
	free(path);
	if (fd < 0)
		return -1;
	if (context)
		do {
			ret = write(fd, context, strlen(context) + 1);
		} while (ret < 0 && errno == EINTR);
	else
		do {
			ret = write(fd, NULL, 0);	/* clear */
		} while (ret < 0 && errno == EINTR);
	errno_hold = errno;
	close(fd);
	errno = errno_hold;
	if (ret < 0)
		return -1;
	else
		return 0;
}

static int setprocattrcon(const security_context_t context,
			  pid_t pid, const char *attr)
{
	int ret;
	security_context_t rcontext;

	if (selinux_trans_to_raw_context(context, &rcontext))
		return -1;

	ret = setprocattrcon_raw(rcontext, pid, attr);

	freecon(rcontext);

	return ret;
}

#define getselfattr_def(fn, attr) \
	int get##fn##_raw(security_context_t *c) \
	{ \
		return getprocattrcon_raw(c, 0, #attr); \
	} \
	int get##fn(security_context_t *c) \
	{ \
		return getprocattrcon(c, 0, #attr); \
	}

#define setselfattr_def(fn, attr) \
	int set##fn##_raw(const security_context_t c) \
	{ \
		return setprocattrcon_raw(c, 0, #attr); \
	} \
	int set##fn(const security_context_t c) \
	{ \
		return setprocattrcon(c, 0, #attr); \
	}

#define all_selfattr_def(fn, attr) \
	getselfattr_def(fn, attr)	 \
	setselfattr_def(fn, attr)

#define getpidattr_def(fn, attr) \
	int get##fn##_raw(pid_t pid, security_context_t *c)	\
	{ \
		return getprocattrcon_raw(c, pid, #attr); \
	} \
	int get##fn(pid_t pid, security_context_t *c)	\
	{ \
		return getprocattrcon(c, pid, #attr); \
	}

all_selfattr_def(con, current)
    getpidattr_def(pidcon, current)
    getselfattr_def(prevcon, prev)
    all_selfattr_def(execcon, exec)
    all_selfattr_def(fscreatecon, fscreate)
    all_selfattr_def(sockcreatecon, sockcreate)
    all_selfattr_def(keycreatecon, keycreate)

    hidden_def(getcon_raw)
    hidden_def(getcon)
    hidden_def(getexeccon_raw)
    hidden_def(getfilecon_raw)
    hidden_def(getfilecon)
    hidden_def(getfscreatecon_raw)
    hidden_def(getkeycreatecon_raw)
    hidden_def(getpeercon_raw)
    hidden_def(getpidcon_raw)
    hidden_def(getprevcon_raw)
    hidden_def(getprevcon)
    hidden_def(getsockcreatecon_raw)
    hidden_def(setcon_raw)
    hidden_def(setexeccon_raw)
    hidden_def(setexeccon)
    hidden_def(setfilecon_raw)
    hidden_def(setfscreatecon_raw)
    hidden_def(setkeycreatecon_raw)
    hidden_def(setsockcreatecon_raw)
