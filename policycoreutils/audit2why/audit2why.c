#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <sepol/sepol.h>
#include <sepol/policydb/services.h>
#include <selinux/selinux.h>

#define AVCPREFIX "avc:  denied  { "
#define SCONTEXT "scontext="
#define TCONTEXT "tcontext="
#define TCLASS "tclass="

void usage(char *progname, int rc)
{
	fprintf(stderr, "usage:  %s [-p policy] < /var/log/audit/audit.log\n",
		progname);
	exit(rc);
}

int main(int argc, char **argv)
{
	char path[PATH_MAX];
	char *buffer = NULL, *bufcopy = NULL;
	unsigned int lineno = 0;
	size_t len = 0, bufcopy_len = 0;
	FILE *fp = NULL;
	int opt, rc, set_path = 0;
	char *p, *scon, *tcon, *tclassstr, *permstr;
	sepol_security_id_t ssid, tsid;
	sepol_security_class_t tclass;
	sepol_access_vector_t perm, av;
	struct sepol_av_decision avd;
	unsigned int reason;
	int vers = 0;
	sidtab_t sidtab;
	policydb_t policydb;
	struct policy_file pf;

	while ((opt = getopt(argc, argv, "p:?h")) > 0) {
		switch (opt) {
		case 'p':
			set_path = 1;
			strncpy(path, optarg, PATH_MAX);
			fp = fopen(path, "r");
			if (!fp) {
				fprintf(stderr, "%s:  unable to open %s:  %s\n",
					argv[0], path, strerror(errno));
				exit(1);
			}
			break;
		default:
			usage(argv[0], 0);
		}
	}

	if (argc - optind)
		usage(argv[0], 1);

	if (!set_path) {
		if (!is_selinux_enabled()) {
			fprintf(stderr,
				"%s:  Must specify -p policy on non-SELinux systems\n",
				argv[0]);
			exit(1);
		}
		vers = security_policyvers();
		if (vers < 0) {
			fprintf(stderr,
				"%s:  Could not get policy version:  %s\n",
				argv[0], strerror(errno));
			exit(1);
		}
		snprintf(path, PATH_MAX, "%s.%d",
			 selinux_binary_policy_path(), vers);
		fp = fopen(path, "r");
		while (!fp && errno == ENOENT && --vers) {
			snprintf(path, PATH_MAX, "%s.%d",
				 selinux_binary_policy_path(), vers);
			fp = fopen(path, "r");
		}
		if (!fp) {
			snprintf(path, PATH_MAX, "%s.%d",
				 selinux_binary_policy_path(),
				 security_policyvers());
			fprintf(stderr, "%s:  unable to open %s:  %s\n",
				argv[0], path, strerror(errno));
			exit(1);
		}
	}

	/* Set up a policydb directly so that we can mutate it later
	   for booleans and user settings.  Otherwise we would just use
	   sepol_set_policydb_from_file() here. */
	pf.fp = fp;
	pf.type = PF_USE_STDIO;
	if (policydb_init(&policydb)) {
		fprintf(stderr, "%s:  policydb_init failed: %s\n",
			argv[0], strerror(errno));
		exit(1);
	}
	if (policydb_read(&policydb, &pf, 0)) {
		fprintf(stderr, "%s:  invalid binary policy %s\n",
			argv[0], path);
		exit(1);
	}
	fclose(fp);
	sepol_set_policydb(&policydb);

	if (!set_path) {
		/* If they didn't specify a full path of a binary policy file,
		   then also try loading any boolean settings and user
		   definitions from the active locations.  Otherwise,
		   they can use genpolbools and genpolusers to build a
		   binary policy file that includes any desired settings
		   and then apply audit2why -p to the resulting file. 
		   Errors are non-fatal as such settings are optional. */
		sepol_debug(0);
		(void)sepol_genbools_policydb(&policydb,
					      selinux_booleans_path());
		(void)sepol_genusers_policydb(&policydb, selinux_users_path());
	}

	/* Initialize the sidtab for subsequent use by sepol_context_to_sid
	   and sepol_compute_av_reason. */
	rc = sepol_sidtab_init(&sidtab);
	if (rc < 0) {
		fprintf(stderr, "%s:  unable to init sidtab\n", argv[0]);
		exit(1);
	}
	sepol_set_sidtab(&sidtab);

	/* Process the audit messages. */
	while (getline(&buffer, &len, stdin) > 0) {
		size_t len2 = strlen(buffer);

		if (buffer[len2 - 1] == '\n')
			buffer[len2 - 1] = 0;
		lineno++;

		p = buffer;
		while (*p && strncmp(p, AVCPREFIX, sizeof(AVCPREFIX) - 1))
			p++;
		if (!(*p))
			continue;	/* not an avc denial */

		p += sizeof(AVCPREFIX) - 1;

		/* Save a copy of the original unmodified buffer. */
		if (!bufcopy) {
			/* Initial allocation */
			bufcopy_len = len;
			bufcopy = malloc(len);
		} else if (bufcopy_len < len) {
			/* Grow */
			bufcopy_len = len;
			bufcopy = realloc(bufcopy, len);
		}
		if (!bufcopy) {
			fprintf(stderr, "%s:  OOM on buffer copy\n", argv[0]);
			exit(2);
		}
		memcpy(bufcopy, buffer, len);

		/* Remember where the permission list begins,
		   and terminate the list. */
		permstr = p;
		while (*p && *p != '}')
			p++;
		if (!(*p)) {
			fprintf(stderr,
				"Missing closing bracket on line %u, skipping...\n",
				lineno);
			continue;
		}
		*p++ = 0;

		/* Get scontext and convert to SID. */
		while (*p && strncmp(p, SCONTEXT, sizeof(SCONTEXT) - 1))
			p++;
		if (!(*p)) {
			fprintf(stderr, "Missing %s on line %u, skipping...\n",
				SCONTEXT, lineno);
			continue;
		}
		p += sizeof(SCONTEXT) - 1;
		scon = p;
		while (*p && !isspace(*p))
			p++;
		if (*p)
			*p++ = 0;
		rc = sepol_context_to_sid(scon, strlen(scon) + 1, &ssid);
		if (rc < 0) {
			fprintf(stderr,
				"Invalid %s%s on line %u, skipping...\n",
				SCONTEXT, scon, lineno);
			continue;
		}

		/* Get tcontext and convert to SID. */
		while (*p && strncmp(p, TCONTEXT, sizeof(TCONTEXT) - 1))
			p++;
		if (!(*p)) {
			fprintf(stderr, "Missing %s on line %u, skipping...\n",
				TCONTEXT, lineno);
			continue;
		}
		p += sizeof(TCONTEXT) - 1;
		tcon = p;
		while (*p && !isspace(*p))
			p++;
		if (*p)
			*p++ = 0;
		rc = sepol_context_to_sid(tcon, strlen(tcon) + 1, &tsid);
		if (rc < 0) {
			fprintf(stderr,
				"Invalid %s%s on line %u, skipping...\n",
				TCONTEXT, tcon, lineno);
			continue;
		}

		/* Get tclass= and convert to value. */
		while (*p && strncmp(p, TCLASS, sizeof(TCLASS) - 1))
			p++;
		if (!(*p)) {
			fprintf(stderr, "Missing %s on line %u, skipping...\n",
				TCLASS, lineno);
			continue;
		}
		p += sizeof(TCLASS) - 1;
		tclassstr = p;
		while (*p && !isspace(*p))
			p++;
		if (*p)
			*p = 0;
		tclass = string_to_security_class(tclassstr);
		if (!tclass) {
			fprintf(stderr,
				"Invalid %s%s on line %u, skipping...\n",
				TCLASS, tclassstr, lineno);
			continue;
		}

		/* Convert the permission list to an AV. */
		p = permstr;
		av = 0;
		while (*p) {
			while (*p && !isspace(*p))
				p++;
			if (*p)
				*p++ = 0;
			perm = string_to_av_perm(tclass, permstr);
			if (!perm) {
				fprintf(stderr,
					"Invalid permission %s on line %u, skipping...\n",
					permstr, lineno);
				continue;
			}
			av |= perm;
			permstr = p;
		}

		/* Reproduce the computation. */
		rc = sepol_compute_av_reason(ssid, tsid, tclass, av, &avd,
					     &reason);
		if (rc < 0) {
			fprintf(stderr,
				"Error during access vector computation on line %u, skipping...\n",
				lineno);
			continue;
		}

		printf("%s\n\tWas caused by:\n", bufcopy);

		if (!reason) {
			printf("\t\tUnknown - would be allowed by %s policy\n",
			       set_path ? "specified" : "active");
			printf
			    ("\t\tPossible mismatch between this policy and the one under which the audit message was generated.\n");
			printf
			    ("\t\tPossible mismatch between current in-memory boolean settings vs. permanent ones.\n");
		}

		if (reason & SEPOL_COMPUTEAV_TE) {
			printf("\t\tMissing or disabled TE allow rule.\n");
			printf
			    ("\t\tAllow rules may exist but be disabled by boolean settings; check boolean settings.\n");
			printf
			    ("\t\tYou can see the necessary allow rules by running audit2allow with this audit message as input.\n");
		}

		if (reason & SEPOL_COMPUTEAV_CONS) {
			printf("\t\tConstraint violation.\n");
			printf("\t\tCheck policy/constraints.\n");
			printf
			    ("\t\tTypically, you just need to add a type attribute to the domain to satisfy the constraint.\n");
		}

		if (reason & SEPOL_COMPUTEAV_RBAC) {
			printf("\t\tMissing role allow rule.\n");
			printf("\t\tAdd allow rule for the role pair.\n");
		}

		printf("\n");
	}
	free(buffer);
	free(bufcopy);
	exit(0);
}
