#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include "selinux_internal.h"
#include "policy.h"

#define UNSET (char *) -1

static __thread char *prev_current = UNSET;
static __thread char * prev_exec = UNSET;
static __thread char * prev_fscreate = UNSET;
static __thread char * prev_keycreate = UNSET;
static __thread char * prev_sockcreate = UNSET;

static pthread_once_t once = PTHREAD_ONCE_INIT;
static pthread_key_t destructor_key;
static int destructor_key_initialized = 0;
static __thread char destructor_initialized;

/* Bionic and glibc >= 2.30 declare gettid() system call wrapper in unistd.h and
 * has a definition for it */
#ifdef __BIONIC__
  #define OVERRIDE_GETTID 0
#elif !defined(__GLIBC_PREREQ)
  #define OVERRIDE_GETTID 1
#elif !__GLIBC_PREREQ(2,30)
  #define OVERRIDE_GETTID 1
#else
  #define OVERRIDE_GETTID 0
#endif

#if OVERRIDE_GETTID
static pid_t gettid(void)
{
	return syscall(__NR_gettid);
}
#endif

static void procattr_thread_destructor(void __attribute__((unused)) *unused)
{
	if (prev_current != UNSET)
		free(prev_current);
	if (prev_exec != UNSET)
		free(prev_exec);
	if (prev_fscreate != UNSET)
		free(prev_fscreate);
	if (prev_keycreate != UNSET)
		free(prev_keycreate);
	if (prev_sockcreate != UNSET)
		free(prev_sockcreate);
}

void __attribute__((destructor)) procattr_destructor(void);

void  __attribute__((destructor)) procattr_destructor(void)
{
	if (destructor_key_initialized)
		__selinux_key_delete(destructor_key);
}

static inline void init_thread_destructor(void)
{
	if (destructor_initialized == 0) {
		__selinux_setspecific(destructor_key, (void *)1);
		destructor_initialized = 1;
	}
}

static void init_procattr(void)
{
	if (__selinux_key_create(&destructor_key, procattr_thread_destructor) == 0) {
		destructor_key_initialized = 1;
	}
}

static int openattr(pid_t pid, const char *attr, int flags)
{
	int fd, rc;
	char *path;
	pid_t tid;

	if (pid > 0) {
		rc = asprintf(&path, "/proc/%d/attr/%s", pid, attr);
	} else if (pid == 0) {
		rc = asprintf(&path, "/proc/thread-self/attr/%s", attr);
		if (rc < 0)
			return -1;
		fd = open(path, flags | O_CLOEXEC);
		if (fd >= 0 || errno != ENOENT)
			goto out;
		free(path);
		tid = gettid();
		rc = asprintf(&path, "/proc/self/task/%d/attr/%s", tid, attr);
	} else {
		errno = EINVAL;
		return -1;
	}
	if (rc < 0)
		return -1;

	fd = open(path, flags | O_CLOEXEC);
out:
	free(path);
	return fd;
}

static int getprocattrcon_raw(char ** context,
			      pid_t pid, const char *attr)
{
	char *buf;
	size_t size;
	int fd;
	ssize_t ret;
	int errno_hold;
	char * prev_context;

	__selinux_once(once, init_procattr);
	init_thread_destructor();

	switch (attr[0]) {
		case 'c':
			prev_context = prev_current;
			break;
		case 'e':
			prev_context = prev_exec;
			break;
		case 'f':
			prev_context = prev_fscreate;
			break;
		case 'k':
			prev_context = prev_keycreate;
			break;
		case 's':
			prev_context = prev_sockcreate;
			break;
		case 'p':
			prev_context = NULL;
			break;
		default:
			errno = ENOENT;
			return -1;
	};

	if (prev_context && prev_context != UNSET) {
		*context = strdup(prev_context);
		if (!(*context)) {
			return -1;
		}
		return 0;
	}

	fd = openattr(pid, attr, O_RDONLY | O_CLOEXEC);
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

static int getprocattrcon(char ** context,
			  pid_t pid, const char *attr)
{
	int ret;
	char * rcontext;

	ret = getprocattrcon_raw(&rcontext, pid, attr);

	if (!ret) {
		ret = selinux_raw_to_trans_context(rcontext, context);
		freecon(rcontext);
	}

	return ret;
}

static int setprocattrcon_raw(const char * context,
			      pid_t pid, const char *attr)
{
	int fd;
	ssize_t ret;
	int errno_hold;
	char **prev_context, *context2 = NULL;

	__selinux_once(once, init_procattr);
	init_thread_destructor();

	switch (attr[0]) {
		case 'c':
			prev_context = &prev_current;
			break;
		case 'e':
			prev_context = &prev_exec;
			break;
		case 'f':
			prev_context = &prev_fscreate;
			break;
		case 'k':
			prev_context = &prev_keycreate;
			break;
		case 's':
			prev_context = &prev_sockcreate;
			break;
		default:
			errno = ENOENT;
			return -1;
	};

	if (!context && !*prev_context)
		return 0;
	if (context && *prev_context && *prev_context != UNSET
	    && !strcmp(context, *prev_context))
		return 0;

	fd = openattr(pid, attr, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return -1;
	if (context) {
		ret = -1;
		context2 = strdup(context);
		if (!context2)
			goto out;
		do {
			ret = write(fd, context2, strlen(context2) + 1);
		} while (ret < 0 && errno == EINTR);
	} else {
		do {
			ret = write(fd, NULL, 0);	/* clear */
		} while (ret < 0 && errno == EINTR);
	}
out:
	errno_hold = errno;
	close(fd);
	errno = errno_hold;
	if (ret < 0) {
		free(context2);
		return -1;
	} else {
		if (*prev_context != UNSET)
			free(*prev_context);
		*prev_context = context2;
		return 0;
	}
}

static int setprocattrcon(const char * context,
			  pid_t pid, const char *attr)
{
	int ret;
	char * rcontext;

	if (selinux_trans_to_raw_context(context, &rcontext))
		return -1;

	ret = setprocattrcon_raw(rcontext, pid, attr);

	freecon(rcontext);

	return ret;
}

#define getselfattr_def(fn, attr) \
	int get##fn##_raw(char **c) \
	{ \
		return getprocattrcon_raw(c, 0, #attr); \
	} \
	int get##fn(char **c) \
	{ \
		return getprocattrcon(c, 0, #attr); \
	}

#define setselfattr_def(fn, attr) \
	int set##fn##_raw(const char * c) \
	{ \
		return setprocattrcon_raw(c, 0, #attr); \
	} \
	int set##fn(const char * c) \
	{ \
		return setprocattrcon(c, 0, #attr); \
	}

#define all_selfattr_def(fn, attr) \
	getselfattr_def(fn, attr)	 \
	setselfattr_def(fn, attr)

#define getpidattr_def(fn, attr) \
	int get##fn##_raw(pid_t pid, char **c)	\
	{ \
		if (pid <= 0) { \
			errno = EINVAL; \
			return -1; \
		} else { \
			return getprocattrcon_raw(c, pid, #attr); \
		} \
	} \
	int get##fn(pid_t pid, char **c)	\
	{ \
		if (pid <= 0) { \
			errno = EINVAL; \
			return -1; \
		} else { \
			return getprocattrcon(c, pid, #attr); \
		} \
	}

all_selfattr_def(con, current)
    getpidattr_def(pidcon, current)
    getselfattr_def(prevcon, prev)
    all_selfattr_def(execcon, exec)
    all_selfattr_def(fscreatecon, fscreate)
    all_selfattr_def(sockcreatecon, sockcreate)
    all_selfattr_def(keycreatecon, keycreate)

