#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/xattr.h>
#include "selinux_internal.h"
#include "policy.h"

int setfilecon_raw(const char *path, const security_context_t context)
{
	return setxattr(path, XATTR_NAME_SELINUX, context, strlen(context) + 1,
			0);
}

hidden_def(setfilecon_raw)

int setfilecon(const char *path, const security_context_t context)
{
	int ret;
	security_context_t rcontext;

	if (selinux_trans_to_raw_context(context, &rcontext))
		return -1;

	ret = setfilecon_raw(path, rcontext);

	freecon(rcontext);

	return ret;
}
