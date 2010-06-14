#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/xattr.h>
#include "selinux_internal.h"
#include "policy.h"

int lsetfilecon_raw(const char *path, const security_context_t context)
{
	return lsetxattr(path, XATTR_NAME_SELINUX, context, strlen(context) + 1,
			 0);
}

hidden_def(lsetfilecon_raw)

int lsetfilecon(const char *path, const security_context_t context)
{
	int ret;
	security_context_t rcontext;

	if (selinux_trans_to_raw_context(context, &rcontext))
		return -1;

	ret = lsetfilecon_raw(path, rcontext);

	freecon(rcontext);

	return ret;
}
