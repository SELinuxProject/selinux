#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mount.h>
#include <sys/vfs.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <linux/lsm.h>

#include "selinux_internal.h"
#include "policy.h"

#ifndef LSM_ATTR_UNSHARE
#define LSM_ATTR_UNSHARE 106
#endif

#ifndef __NR_lsm_get_self_attr
#define __NR_lsm_get_self_attr 459
#endif

#ifndef __NR_lsm_set_self_attr
#define __NR_lsm_set_self_attr 460
#endif

#ifndef HAVE_LSM_SET_SELF_ATTR
#define HAVE_LSM_SET_SELF_ATTR 1
static int lsm_set_self_attr(unsigned int attr, struct lsm_ctx *ctx,
			     uint32_t size, uint32_t flags)
{
	return syscall(__NR_lsm_set_self_attr, attr, ctx, size, flags);
}
#endif

#ifndef HAVE_LSM_GET_SELF_ATTR
#define HAVE_LSM_GET_SELF_ATTR 1
static int lsm_get_self_attr(unsigned int attr, struct lsm_ctx *ctx,
			     uint32_t *size, uint32_t flags)
{
	return syscall(__NR_lsm_get_self_attr, attr, ctx, size, flags);
}
#endif

/*
 * Precondition: caller must have already done unshare(CLONE_NEWNS) or
 * been created via clone(CLONE_NEWNS) and mounted a MS_REC|MS_PRIVATE
 * / filesystem so that any pre-existing selinuxfs mount can be
 * modified freely by selinux_unshare(). See ../utils/unshareselinux.c
 * for an example.
 */
int selinux_unshare(void)
{
	struct lsm_ctx ctx;
	int ret;

	ctx.id = LSM_ID_SELINUX;
	ctx.flags = 0;
	ctx.len = sizeof(ctx);
	ctx.ctx_len = 0;

	/* Unshare the SELinux namespace */
	ret = lsm_set_self_attr(LSM_ATTR_UNSHARE, &ctx, sizeof(ctx), 0);
	if (ret < 0)
		return -1;

	/* Unmount the selinuxfs which refers to the old/parent namespace */
	ret = umount(SELINUXMNT);
	if (ret < 0)
		return ret;

	/*
	 * Caller is responsible for mounting new selinuxfs, loading policy,
	 * setting enforcing mode, etc.
	 */

	return 0;
}

struct selinux_ctx {
	struct lsm_ctx lsmctx;
	char unshared;
};

/*
 * Returns 1 if the SELinux namespace was unshared and has not
 * yet been fully initialized (i.e. policy not yet loaded).
 * Returns 0 if SELinux namespaces are not supported by the kernel,
 * or the SELinux namespace was not unshared, or the namespace has
 * been fully initialized already.
 * Return < 0 on any error other than ENOSYS or EOPNOTSUPP.
 */
int is_selinux_unshared(void)
{
	struct selinux_ctx ctx;
	uint32_t size = sizeof(ctx);
	int ret;

	ctx.lsmctx.id = LSM_ID_SELINUX;
	ctx.lsmctx.flags = 0;
	ctx.lsmctx.len = sizeof(ctx);
	ctx.lsmctx.ctx_len = 0;

	ret = lsm_get_self_attr(LSM_ATTR_UNSHARE, (struct lsm_ctx *)&ctx,
				&size, LSM_FLAG_SINGLE);
	if (ret < 0 && (errno == ENOSYS || errno == EOPNOTSUPP))
		return 0;
	if (ret < 0)
		return ret;
	return ctx.unshared;
}
