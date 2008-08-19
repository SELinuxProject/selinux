/*
 * Policy capability support functions
 */

#include <string.h>
#include <sepol/policydb/polcaps.h>

static const char *polcap_names[] = {
	"network_peer_controls",	/* POLICYDB_CAPABILITY_NETPEER */
	"open_perms",			/* POLICYDB_CAPABILITY_OPENPERM */
	NULL
};

int sepol_polcap_getnum(const char *name)
{
	int capnum;

	for (capnum = 0; capnum <= POLICYDB_CAPABILITY_MAX; capnum++) {
		if (polcap_names[capnum] == NULL)
			continue;
		if (strcasecmp(polcap_names[capnum], name) == 0)
			return capnum;
	}
	return -1;
}

const char *sepol_polcap_getname(int capnum)
{
	if (capnum > POLICYDB_CAPABILITY_MAX)
		return NULL;

	return polcap_names[capnum];
}
