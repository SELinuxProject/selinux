#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <dlfcn.h>
#include <sys/statvfs.h>
#include <sys/vfs.h>
#include <stdint.h>
#include <limits.h>

#include "policy.h"
#include "selinux_internal.h"
#include "setrans_internal.h"

char *selinux_mnt = NULL;
size_t selinux_page_size = 0;

int has_selinux_config = 0;

/* Verify the mount point for selinux file system has a selinuxfs.
   If the file system:
   * Exist,
   * Is mounted with an selinux file system,
   * The file system is read/write
   * then set this as the default file system.
*/
static int verify_selinuxmnt(const char *mnt)
{
	struct statfs sfbuf;
	int rc;

	do {
		rc = statfs(mnt, &sfbuf);
	} while (rc < 0 && errno == EINTR);
	if (rc == 0) {
		if ((uint32_t)sfbuf.f_type == (uint32_t)SELINUX_MAGIC) {
			struct statvfs vfsbuf;
			rc = statvfs(mnt, &vfsbuf);
			if (rc == 0) {
				if (!(vfsbuf.f_flag & ST_RDONLY)) {
					set_selinuxmnt(mnt);
				}
				return 0;
			}
		}
	}

	return -1;
}

int selinuxfs_exists(void)
{
	int exists = 0;
	FILE *fp = NULL;
	char *buf = NULL;
	size_t len;
	ssize_t num;

	fp = fopen("/proc/filesystems", "re");
	if (!fp)
		return 1; /* Fail as if it exists */
	__fsetlocking(fp, FSETLOCKING_BYCALLER);

	num = getline(&buf, &len, fp);
	while (num != -1) {
		if (strstr(buf, SELINUXFS)) {
			exists = 1;
			break;
		}
		num = getline(&buf, &len, fp);
	}

	free(buf);
	fclose(fp);
	return exists;
}

static void init_selinuxmnt(void)
{
	if (selinux_mnt)
		return;

	if (verify_selinuxmnt(SELINUXMNT) == 0)
		return;
}

void fini_selinuxmnt(void)
{
	free(selinux_mnt);
	selinux_mnt = NULL;
}

void set_selinuxmnt(const char *mnt)
{
	selinux_mnt = strdup(mnt);
}

static void init_lib(void) __attribute__((constructor));
static void init_lib(void)
{
	long page_size;
#ifndef ANDROID
	unsigned int i;
	char cfg[PATH_MAX];
#endif

	SELINUX_PROTECT_ERRNO;
	page_size = sysconf(_SC_PAGE_SIZE);
	/* Fall back to a sane default if sysconf() fails or returns an implausible value. */
	selinux_page_size = (page_size > 0 && page_size <= INT_MAX) ?
				    (size_t)page_size :
				    4096;
	init_selinuxmnt();
#ifndef ANDROID
	for (i = 0; selinux_confdirs[i]; i++) {
		snprintf(cfg, sizeof(cfg), "%sconfig", selinux_confdirs[i]);
		if (access(cfg, F_OK) == 0) {
			has_selinux_config = 1;
			break;
		}
	}
#endif
}

static void fini_lib(void) __attribute__((destructor));
static void fini_lib(void)
{
	fini_selinuxmnt();
}
