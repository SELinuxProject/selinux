#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <errno.h>
#include "selinux_internal.h"
#include <selinux/flask.h>
#include <selinux/av_permissions.h>

int selinux_check_passwd_access(access_vector_t requested)
{
	int status = -1;
	security_context_t user_context;
	if (is_selinux_enabled() == 0)
		return 0;
	if (getprevcon_raw(&user_context) == 0) {
		security_class_t passwd_class;
		struct av_decision avd;
		int retval;

		passwd_class = string_to_security_class("passwd");
		if (passwd_class == 0)
			return 0;

		retval = security_compute_av_raw(user_context,
						     user_context,
						     passwd_class,
						     requested,
						     &avd);

		if ((retval == 0) && ((requested & avd.allowed) == requested)) {
			status = 0;
		}
		freecon(user_context);
	}

	if (status != 0 && security_getenforce() == 0)
		status = 0;

	return status;
}

hidden_def(selinux_check_passwd_access)

int checkPasswdAccess(access_vector_t requested)
{
	return selinux_check_passwd_access(requested);
}
