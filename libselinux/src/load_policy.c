#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include "selinux_internal.h"
#include <sepol/sepol.h>
#include <sepol/policydb.h>
#include "policy.h"
#include <limits.h>

int security_load_policy(void *data, size_t len)
{
	char path[PATH_MAX];
	int fd, ret;

	if (!selinux_mnt) {
		errno = ENOENT;
		return -1;
	}

	snprintf(path, sizeof path, "%s/load", selinux_mnt);
	fd = open(path, O_RDWR);
	if (fd < 0)
		return -1;

	ret = write(fd, data, len);
	close(fd);
	if (ret < 0)
		return -1;
	return 0;
}

hidden_def(security_load_policy)

int load_setlocaldefs hidden = 1;

int selinux_mkload_policy(int preservebools)
{
	int vers = sepol_policy_kern_vers_max();
	int kernvers = security_policyvers();
	char path[PATH_MAX], **names;
	struct stat sb;
	size_t size;
	void *map, *data;
	int fd, rc = -1, *values, len, i, prot;
	sepol_policydb_t *policydb;
	sepol_policy_file_t *pf;

      search:
	snprintf(path, sizeof(path), "%s.%d",
		 selinux_binary_policy_path(), vers);
	fd = open(path, O_RDONLY);
	while (fd < 0 && errno == ENOENT
	       && --vers >= sepol_policy_kern_vers_min()) {
		/* Check prior versions to see if old policy is available */
		snprintf(path, sizeof(path), "%s.%d",
			 selinux_binary_policy_path(), vers);
		fd = open(path, O_RDONLY);
	}
	if (fd < 0)
		return -1;

	if (fstat(fd, &sb) < 0)
		goto close;

	prot = PROT_READ;
	if (load_setlocaldefs || preservebools)
		prot |= PROT_WRITE;

	size = sb.st_size;
	data = map = mmap(NULL, size, prot, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED)
		goto close;

	if (vers > kernvers) {
		/* Need to downgrade to kernel-supported version. */
		if (sepol_policy_file_create(&pf))
			goto unmap;
		if (sepol_policydb_create(&policydb)) {
			sepol_policy_file_free(pf);
			goto unmap;
		}
		sepol_policy_file_set_mem(pf, data, size);
		if (sepol_policydb_read(policydb, pf)) {
			sepol_policy_file_free(pf);
			sepol_policydb_free(policydb);
			goto unmap;
		}
		if (sepol_policydb_set_vers(policydb, kernvers) ||
		    sepol_policydb_to_image(NULL, policydb, &data, &size)) {
			/* Downgrade failed, keep searching. */
			sepol_policy_file_free(pf);
			sepol_policydb_free(policydb);
			munmap(map, sb.st_size);
			close(fd);
			vers--;
			goto search;
		}
		sepol_policy_file_free(pf);
		sepol_policydb_free(policydb);
	}

	if (load_setlocaldefs) {
		void *olddata = data;
		size_t oldsize = size;
		rc = sepol_genusers(olddata, oldsize, selinux_users_path(),
				    &data, &size);
		if (rc < 0) {
			/* Fall back to the prior image if genusers failed. */
			data = olddata;
			size = oldsize;
			rc = 0;
		} else {
			if (olddata != map)
				free(olddata);
		}
	}

	if (preservebools) {
		rc = security_get_boolean_names(&names, &len);
		if (!rc) {
			values = malloc(sizeof(int) * len);
			if (!values)
				goto unmap;
			for (i = 0; i < len; i++)
				values[i] =
				    security_get_boolean_active(names[i]);
			(void)sepol_genbools_array(data, size, names, values,
						   len);
			free(values);
			for (i = 0; i < len; i++)
				free(names[i]);
			free(names);
		}
	} else if (load_setlocaldefs) {
		(void)sepol_genbools(data, size,
				     (char *)selinux_booleans_path());
	}

	rc = security_load_policy(data, size);

      unmap:
	if (data != map)
		free(data);
	munmap(map, sb.st_size);
      close:
	close(fd);
	return rc;
}

hidden_def(selinux_mkload_policy)

/*
 * Mount point for selinuxfs. 
 * This definition is private to the function below.
 * Everything else uses the location determined during 
 * libselinux startup via /proc/mounts (see init_selinuxmnt).  
 * We only need the hardcoded definition for the initial mount 
 * required for the initial policy load.
 */
#define SELINUXMNT "/selinux/"
int selinux_init_load_policy(int *enforce)
{
	int rc = 0, orig_enforce = 0, seconfig = -2, secmdline = -1;
	FILE *cfg;
	char *buf;

	/*
	 * Get desired mode (disabled, permissive, enforcing) from 
	 * /etc/selinux/config. 
	 */
	selinux_getenforcemode(&seconfig);

	/* Check for an override of the mode via the kernel command line. */
	rc = mount("none", "/proc", "proc", 0, 0);
	cfg = fopen("/proc/cmdline", "r");
	if (cfg) {
		char *tmp;
		buf = malloc(selinux_page_size);
		if (!buf) {
			fclose(cfg);
			return -1;
		}
		if (fgets(buf, selinux_page_size, cfg) &&
		    (tmp = strstr(buf, "enforcing="))) {
			if (tmp == buf || isspace(*(tmp - 1))) {
				secmdline =
				    atoi(tmp + sizeof("enforcing=") - 1);
			}
		}
		fclose(cfg);
		free(buf);
	}
#define MNT_DETACH 2
	if (rc == 0)
		umount2("/proc", MNT_DETACH);

	/* 
	 * Determine the final desired mode.
	 * Command line argument takes precedence, then config file. 
	 */
	if (secmdline >= 0)
		*enforce = secmdline;
	else if (seconfig >= 0)
		*enforce = seconfig;
	else
		*enforce = 0;	/* unspecified or disabled */

	/*
	 * Check for the existence of SELinux via selinuxfs, and 
	 * mount it if present for use in the calls below.  
	 */
	if (mount("none", SELINUXMNT, "selinuxfs", 0, 0) < 0) {
		if (errno == ENODEV) {
			/*
			 * SELinux was disabled in the kernel, either
			 * omitted entirely or disabled at boot via selinux=0.
			 * This takes precedence over any config or
			 * commandline enforcing setting.
			 */
			*enforce = 0;
		}
		fprintf(stderr, "Mount failed for selinuxfs on %s:  %s\n", SELINUXMNT, strerror(errno));
		goto noload;
	}
	set_selinuxmnt(SELINUXMNT);

	/*
	 * Note:  The following code depends on having selinuxfs 
	 * already mounted and selinuxmnt set above.
	 */

	if (seconfig == -1) {
		/* Runtime disable of SELinux. */
		rc = security_disable();
		if (rc == 0) {
			/* Successfully disabled, so umount selinuxfs too. */
			umount(SELINUXMNT);
		}
		/*
		 * If we failed to disable, SELinux will still be 
		 * effectively permissive, because no policy is loaded. 
		 * No need to call security_setenforce(0) here.
		 */
		goto noload;
	}

	/*
	 * If necessary, change the kernel enforcing status to match 
	 * the desired mode. 
	 */
	orig_enforce = rc = security_getenforce();
	if (rc < 0)
		goto noload;
	if (orig_enforce != *enforce) {
		rc = security_setenforce(*enforce);
		if (rc < 0)
			goto noload;
	}

	/* Load the policy. */
	return selinux_mkload_policy(0);

      noload:
	/*
	 * Only return 0 on a successful completion of policy load.
	 * In any other case, we want to return an error so that init
	 * knows not to proceed with the re-exec for the domain transition.
	 * Depending on the *enforce setting, init will halt (> 0) or proceed
	 * normally (otherwise).
	 */
	return -1;
}
