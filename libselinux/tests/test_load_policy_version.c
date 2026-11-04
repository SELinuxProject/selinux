#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sepol/cil/cil.h>
#include <selinux/selinux.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static unsigned kernel_version, submitted, conversions, failures;
static int testing;
static char root[] = "/tmp/selinux-load-version-XXXXXX";
static char base[256];
static const char *roots[] = { root, NULL, NULL };

extern void fini_selinuxmnt(void);

int __wrap_security_policyvers(void);
const char *const *__wrap_selinux_policy_roots(void);
const char *__wrap_selinux_binary_policy_path(void);
int __wrap_sepol_policydb_to_image(sepol_handle_t *handle, sepol_policydb_t *p,
				   void **data, size_t *len);
ssize_t __wrap_write(int fd, const void *data, size_t len);

int __wrap_security_policyvers(void)
{
	return kernel_version;
}

const char *const *__wrap_selinux_policy_roots(void)
{
	return roots;
}

const char *__wrap_selinux_binary_policy_path(void)
{
	return base;
}

int __real_sepol_policydb_to_image(sepol_handle_t *, sepol_policydb_t *,
				   void **, size_t *);
int __wrap_sepol_policydb_to_image(sepol_handle_t *handle, sepol_policydb_t *p,
				   void **data, size_t *len)
{
	if (testing) {
		conversions++;
		if (failures) {
			failures--;
			errno = ENOMEM;
			return -1;
		}
	}
	return __real_sepol_policydb_to_image(handle, p, data, len);
}

ssize_t __real_write(int, const void *, size_t);
static uint32_t image_word(const unsigned char *data, size_t len, size_t offset)
{
	assert(offset <= len && len - offset >= sizeof(uint32_t));
	return (uint32_t)data[offset] | ((uint32_t)data[offset + 1] << 8) |
	       ((uint32_t)data[offset + 2] << 16) |
	       ((uint32_t)data[offset + 3] << 24);
}

ssize_t __wrap_write(int fd, const void *data, size_t len)
{
	uint32_t target_len;

	if (!testing)
		return __real_write(fd, data, len);
	/* The version follows the magic, target length and target string. */
	assert(image_word(data, len, 0) == UINT32_C(0xf97cff8c));
	target_len = image_word(data, len, 4);
	assert(target_len == strlen("SE Linux"));
	assert(len >= 8 && target_len <= len - 8);
	assert(memcmp((const unsigned char *)data + 8, "SE Linux",
		      target_len) == 0);
	submitted = image_word(data, len, 8 + target_len);
	if (submitted > kernel_version) {
		errno = EINVAL;
		return -1;
	}
	return len;
}

static void policy_file(sepol_policydb_t *p, unsigned version, int remove)
{
	char path[512];
	void *image;
	size_t size;
	FILE *fp;

	snprintf(path, sizeof(path), "%s.%u", base, version);
	if (remove) {
		assert(unlink(path) == 0);
		return;
	}
	assert(sepol_policydb_set_vers(p, version) == 0);
	assert(sepol_policydb_to_image(NULL, p, &image, &size) == 0);
	fp = fopen(path, "we");
	assert(fp);
	assert(fwrite(image, 1, size, fp) == size);
	assert(fclose(fp) == 0);
	free(image);
}

static void load(unsigned expected_version, unsigned expected_conversions)
{
	int rc;

	submitted = conversions = 0;
	testing = 1;
	rc = selinux_mkload_policy(0);
	testing = 0;
	assert(rc == (expected_version ? 0 : -1));
	assert(submitted == expected_version);
	assert(conversions == expected_conversions);
}

int main(void)
{
	const char cil[] =
		"(class file (read)) (classorder (file)) (sid kernel) (sidorder (kernel)) "
		"(user u) (role r) (type t) (category c0) (categoryorder (c0)) "
		"(sensitivity s0) (sensitivityorder (s0)) (sensitivitycategory s0 (c0)) "
		"(allow t self (file (read))) (roletype r t) (userrole u r) "
		"(userlevel u (s0)) (userrange u ((s0)(s0 (c0)))) "
		"(sidcontext kernel (u r t ((s0)(s0))))";
	cil_db_t *db;
	sepol_policydb_t *p;
	unsigned min = sepol_policy_kern_vers_min();
	unsigned max = sepol_policy_kern_vers_max();
	unsigned cases = 0;
	char path[256];
	int fd;

	assert(max >= min + 2);
	cil_db_init(&db);
	assert(db);
	cil_set_mls(db, 1);
	assert(cil_add_file(db, "test.cil", cil, sizeof(cil) - 1) == 0);
	assert(cil_compile(db) == 0);
	assert(cil_build_policydb(db, &p) == 0);
	cil_db_destroy(&db);
	assert(mkdtemp(root));
	snprintf(path, sizeof(path), "%s/policy", root);
	assert(mkdir(path, 0700) == 0);
	snprintf(base, sizeof(base), "%s/policy/policy", root);
	snprintf(path, sizeof(path), "%s/load", root);
	fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
	assert(fd >= 0 && close(fd) == 0);
	fini_selinuxmnt();
	set_selinuxmnt(root);

	for (unsigned older = 0; older < 2; older++) {
		for (unsigned source = min; source <= max; source++) {
			for (unsigned gap = 0; gap <= 2 && gap <= source - min;
			     gap++) {
				kernel_version = source - gap;
				policy_file(p, source, 0);
				if (older && gap)
					policy_file(p, kernel_version, 0);
				load(kernel_version, gap ? 1 : 0);
				policy_file(p, source, 1);
				if (older && gap)
					policy_file(p, kernel_version, 1);
				cases++;
			}
		}
	}

	/* A failed conversion must try the immediately preceding version. */
	kernel_version = max - 2;
	policy_file(p, max, 0);
	policy_file(p, max - 1, 0);
	failures = 1;
	load(kernel_version, 2);
	cases++;
	failures = 2;
	load(0, 2);
	cases++;
	/* An already compatible fallback does not need another conversion. */
	policy_file(p, max - 1, 1);
	policy_file(p, kernel_version, 0);
	failures = 1;
	load(kernel_version, 1);
	cases++;
	policy_file(p, max, 1);
	policy_file(p, kernel_version, 1);
	load(0, 0);
	cases++;

	/* Root fallback must preserve the version, too. */
	policy_file(p, max, 0);
	roots[0] = base;
	roots[1] = root;
	kernel_version = max - 1;
	load(kernel_version, 1);
	cases++;
	/* A non-searchable path component is still a hard error. */
	roots[0] = path;
	load(0, 0);
	cases++;
	roots[0] = root;
	roots[1] = NULL;
	policy_file(p, max, 1);

	fini_selinuxmnt();
	sepol_policydb_free(p);
	assert(unlink(path) == 0);
	snprintf(path, sizeof(path), "%s/policy", root);
	assert(rmdir(path) == 0 && rmdir(root) == 0);
	printf("load-policy-version: %u cases passed\n", cases);
	return 0;
}
