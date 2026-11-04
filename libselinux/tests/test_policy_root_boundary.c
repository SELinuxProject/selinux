#define _GNU_SOURCE
#include <assert.h>
#include <sys/stat.h>
#include <selinux/label.h>
/* Install isolated roots without changing the host configuration. */
#include "../src/selinux_config.c"

static void put(const char *path, const char *type)
{
	FILE *fp = fopen(path, "we");
	assert(fp);
	assert(fprintf(fp, "disk system_u:object_r:%s:s0\n", type) > 0);
	assert(fclose(fp) == 0);
}

static void check(const char *path, const char *expected, const char *resolved)
{
	char text[128], actual[PATH_MAX];
	int fd = selinux_policy_open(path, O_RDONLY | O_CLOEXEC);
	if (expected) {
		assert(fd >= 0);
		ssize_t n = read(fd, text, sizeof(text) - 1);
		assert(n > 0);
		text[n] = '\0';
		assert(strstr(text, expected));
		assert(close(fd) == 0);
	} else
		assert(fd == -1 && errno == ENOENT);
	FILE *fp = selinux_policy_fopen(path, "re");
	if (expected) {
		assert(fp && fgets(text, sizeof(text), fp));
		assert(strstr(text, expected) && fclose(fp) == 0);
	} else
		assert(!fp && errno == ENOENT);
	int rc = selinux_policy_resolve(path, NULL, actual, sizeof(actual));
	if (expected)
		assert(rc == 0 && !strcmp(actual, resolved));
	else
		assert(rc == -1 && errno == ENOENT && !strcmp(actual, path));
	struct selinux_opt opt = { SELABEL_OPT_PATH, path };
	struct selabel_handle *h = selabel_open(SELABEL_CTX_MEDIA, &opt, 1);
	if (expected) {
		char *context = NULL;
		assert(h && selabel_lookup_raw(h, &context, "disk", 0) == 0);
		assert(strstr(context, expected));
		freecon(context);
		selabel_close(h);
	} else
		assert(!h && errno == ENOENT);
}

int main(void)
{
	char tmp[] = "/tmp/selinux-root-boundary-XXXXXX";
	char admin[256], vendor[256], adir[512], vdir[512];
	char path[600], alt[600], resolved[600];
	const char *suffixes[] = { "", ".backup", "2", "-other" };
	unsigned cases = 0;
	assert(mkdtemp(tmp));
	snprintf(admin, sizeof(admin), "%s/admin", tmp);
	snprintf(vendor, sizeof(vendor), "%s/vendor", tmp);
	assert(selinux_set_policy_root(admin) == 0);
	selinux_policyroots[1] = strdup(vendor);
	assert(selinux_policyroots[1]);
	/* Exact roots and descendants qualify; sibling names and ancestors do not. */
	assert(selinux_policy_remap(admin, vendor, resolved,
				    sizeof(resolved)) == 0);
	assert(!strcmp(resolved, vendor));
	assert(selinux_policy_remap(tmp, vendor, resolved, sizeof(resolved)) ==
	       -1);
	assert(selinux_policy_remap("", vendor, resolved, sizeof(resolved)) ==
	       -1);
	cases += 3;
	for (unsigned i = 0; i < 4; i++) {
		snprintf(adir, sizeof(adir), "%s%s", admin, suffixes[i]);
		snprintf(vdir, sizeof(vdir), "%s%s", vendor, suffixes[i]);
		assert(mkdir(adir, 0700) == 0 && mkdir(vdir, 0700) == 0);
		snprintf(path, sizeof(path), "%s/media", adir);
		snprintf(alt, sizeof(alt), "%s/media", vdir);
		put(alt, "vendor_t");
		check(path, i ? NULL : "vendor_t", alt);
		cases++;
		assert(unlink(alt) == 0);
		check(path, NULL, NULL);
		cases++;
		/* A compiled sibling can only establish existence inside the root. */
		strcat(alt, ".bin");
		put(alt, "vendor_t");
		int rc = selinux_policy_resolve(path, ".bin", resolved,
						sizeof(resolved));
		alt[strlen(alt) - 4] = '\0';
		if (i)
			assert(rc == -1 && errno == ENOENT &&
			       !strcmp(resolved, path));
		else
			assert(rc == 0 && !strcmp(resolved, alt));
		cases++;
		strcat(alt, ".bin");
		assert(unlink(alt) == 0);
		alt[strlen(alt) - 4] = '\0';
		put(alt, "vendor_t");
		put(path, "admin_t");
		check(path, "admin_t", path);
		cases++;
		assert(unlink(path) == 0 && unlink(alt) == 0);
		assert(rmdir(adir) == 0 && rmdir(vdir) == 0);
	}
	assert(mkdir(vendor, 0700) == 0);
	snprintf(path, sizeof(path), "%s/media", admin);
	snprintf(alt, sizeof(alt), "%s/media", vendor);
	put(alt, "vendor_t");
	assert(selinux_set_policy_root(admin) == 0);
	check(path, NULL, NULL);
	cases++;
	assert(unlink(alt) == 0 && rmdir(vendor) == 0 && rmdir(tmp) == 0);
	printf("policy-root-boundary: %u scenarios passed\n", cases);
	return 0;
}
