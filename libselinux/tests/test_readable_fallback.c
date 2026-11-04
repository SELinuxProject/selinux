/* SPDX-License-Identifier: CC0-1.0 */
#define _GNU_SOURCE
#undef NDEBUG
#include <assert.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <selinux/label.h>
/* Use private configuration roots without modifying host configuration. */
#include "../src/selinux_config.c"

static const char *suffixes[] = { "",	   ".local",	 ".homedirs",
				  ".subs", ".subs_dist", ".bin" };
static const char *compiler;

static void put(const char *path, const char *text, bool readable)
{
	bool binary = strlen(path) >= 4 &&
		      !strcmp(path + strlen(path) - 4, ".bin");
	char source[] = "/tmp/selinux-readable-source-XXXXXX";
	int fd = binary ? mkstemp(source) : -1;
	assert(!binary || fd >= 0);
	FILE *fp = binary ? fdopen(fd, "w") : fopen(path, "we");
	assert(fp);
	assert(fputs(text, fp) >= 0);
	assert(fclose(fp) == 0);
	if (binary) {
		pid_t pid = fork();
		assert(pid >= 0);
		if (!pid) {
			execl(compiler, compiler, "-o", path, source,
			      (char *)NULL);
			_exit(127);
		}
		int status;
		assert(waitpid(pid, &status, 0) == pid);
		assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
		assert(unlink(source) == 0);
	}
	assert(chmod(path, readable ? 0600 : 0000) == 0);
}

static void root_dir(const char *root, bool create)
{
	char path[PATH_MAX];
	if (create) {
		assert(mkdir(root, 0700) == 0);
		snprintf(path, sizeof(path), "%s/contexts", root);
		assert(mkdir(path, 0700) == 0);
		snprintf(path, sizeof(path), "%s/contexts/files", root);
		assert(mkdir(path, 0700) == 0);
	} else {
		for (size_t i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]);
		     i++) {
			snprintf(path, sizeof(path),
				 "%s/contexts/files/file_contexts%s", root,
				 suffixes[i]);
			assert(unlink(path) == 0 || errno == ENOENT);
		}
		snprintf(path, sizeof(path), "%s/contexts/files", root);
		assert(rmdir(path) == 0);
		snprintf(path, sizeof(path), "%s/contexts", root);
		assert(rmdir(path) == 0);
		assert(rmdir(root) == 0);
	}
}

/* mode: missing admin, readable admin, unreadable admin, vendor-only denial,
 * both denied; sibling modes add readable/unreadable text next to .bin. */
static void run(unsigned input, unsigned mode)
{
	char tmp[] = "/tmp/selinux-readable-XXXXXX";
	char admin[256], vendor[256], path[PATH_MAX], alt[PATH_MAX];
	const char *admin_text = "/probe system_u:object_r:admin_t:s0\n";
	const char *vendor_text = "/probe system_u:object_r:vendor_t:s0\n"
				  "/admin system_u:object_r:admin_t:s0\n"
				  "/vendor system_u:object_r:vendor_t:s0\n";
	assert(mkdtemp(tmp));
	snprintf(admin, sizeof(admin), "%s/admin", tmp);
	snprintf(vendor, sizeof(vendor), "%s/vendor", tmp);
	root_dir(admin, true);
	root_dir(vendor, true);
	assert(selinux_set_policy_root(admin) == 0);
	selinux_policyroots[1] = strdup(vendor);
	assert(selinux_policyroots[1]);
	if (input != 0 && input != 5) {
		snprintf(path, sizeof(path), "%s/contexts/files/file_contexts",
			 admin);
		put(path, vendor_text, true);
	}
	snprintf(path, sizeof(path), "%s/contexts/files/file_contexts%s", admin,
		 suffixes[input]);
	snprintf(alt, sizeof(alt), "%s/contexts/files/file_contexts%s", vendor,
		 suffixes[input]);
	put(alt, input == 3 || input == 4 ? "/probe /vendor\n" : vendor_text,
	    mode < 3 || mode > 4);
	if (mode != 0 && mode != 3)
		put(path,
		    input == 3 || input == 4 ? "/probe /admin\n" : admin_text,
		    mode == 1 || mode == 6);
	if (input == 5 && mode >= 5) {
		snprintf(path, sizeof(path), "%s/contexts/files/file_contexts",
			 admin);
		put(path, vendor_text, mode == 5);
		/* Make .bin newer: an unreadable newer sibling must not mask text. */
		struct timespec times[2] = { { 2000000000, 0 },
					     { 2000000000, 0 } };
		snprintf(path, sizeof(path),
			 "%s/contexts/files/file_contexts.bin", admin);
		assert(utimensat(AT_FDCWD, path, times, 0) == 0);
	}
	errno = 0;
	struct selabel_handle *h = selabel_open(SELABEL_CTX_FILE, NULL, 0);
	if (mode == 3 || mode == 4) {
		assert(h == NULL && errno == EACCES);
	} else {
		char *context = NULL;
		assert(h);
		assert(selabel_lookup_raw(h, &context, "/probe", S_IFREG) == 0);
		assert(strstr(context, mode == 1 || mode == 6 ? ":admin_t:" :
								":vendor_t:"));
		freecon(context);
		selabel_close(h);
	}
	root_dir(admin, false);
	root_dir(vendor, false);
	assert(rmdir(tmp) == 0);
}

int main(int argc, char **argv)
{
	assert(argc == 2);
	compiler = argv[1];
	/* faccessat must observe ordinary DAC permissions, not root override. */
	if (geteuid() == 0)
		assert(setuid(65534) == 0);
	(void)selinux_policy_root();
	unsigned cases = 0;
	for (unsigned input = 0; input < 6; input++) {
		for (unsigned mode = 0; mode < (input == 5 ? 7U : 5U); mode++) {
			run(input, mode);
			cases++;
		}
	}
	printf("Readable configuration fallback: %u cases passed.\n", cases);
	return 0;
}
