#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <errno.h>
#include "selinux_internal.h"
#include <selinux/flask.h>
#include <selinux/avc.h>
#include <selinux/av_permissions.h>

static pthread_once_t once = PTHREAD_ONCE_INIT;

static void avc_init_once(void)
{
	avc_open(NULL, 0);
}

int selinux_check_access(const security_context_t scon, const security_context_t tcon, const char *class, const char *perm, void *aux) {
	int status = -1;
	int rc = -1;
	security_id_t scon_id;
	security_id_t tcon_id;
	security_class_t sclass;
	access_vector_t av;

	if (is_selinux_enabled() == 0)
		return 0;

	__selinux_once(once, avc_init_once);

	if ((rc = avc_context_to_sid(scon, &scon_id)) < 0)  return rc;

	if ((rc = avc_context_to_sid(tcon, &tcon_id)) < 0)  return rc;

	if ((sclass = string_to_security_class(class)) == 0) return status;

	if ((av = string_to_av_perm(sclass, perm)) == 0) return status;

	return avc_has_perm (scon_id, tcon_id, sclass, av, NULL, aux);
}

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
