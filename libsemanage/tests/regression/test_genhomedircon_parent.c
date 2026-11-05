/* SPDX-License-Identifier: CC0-1.0 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#undef NDEBUG
#include <assert.h>
#include <stdarg.h>
#ifndef GENERATOR_SOURCE
#define GENERATOR_SOURCE "../../src/genhomedircon.c"
#endif
#include GENERATOR_SOURCE
#include <selinux/label.h>

static const char *home;
static const char *conflict;
static unsigned calls, failures;
static unsigned fail_at, rewrite_calls;
static bool iterator_error;

char *__wrap_semanage_findval(const char *file, const char *key,
			      const char *sep);
char *__wrap_semanage_findval(const char *file, const char *key,
			      const char *sep)
{
	(void)file;
	(void)sep;
	return !strcmp(key, "HOME") ? strdup("/home") : NULL;
}

void __wrap_setpwent(void);
void __wrap_endpwent(void);
struct passwd *__wrap_getpwent(void);
void __wrap_setpwent(void)
{
	calls = 0;
}
void __wrap_endpwent(void)
{
}
struct passwd *__wrap_getpwent(void)
{
	static char directory[256], name[] = "alice", shell[] = "/bin/bash";
	static struct passwd pw = { .pw_name = name,
				    .pw_uid = 1000,
				    .pw_gid = 1000,
				    .pw_shell = shell,
				    .pw_dir = directory };
	assert(strlen(home) < sizeof(directory));
	strcpy(directory, home);
	return calls++ == 0 ? &pw : NULL;
}

FILE *__real_fopen(const char *path, const char *mode);
FILE *__wrap_fopen(const char *path, const char *mode);
FILE *__wrap_fopen(const char *path, const char *mode)
{
	if (!strcmp(path, PATH_SHELLS_FILE) ||
	    !strcmp(path, PATH_ETC_LOGIN_DEFS) ||
	    !strcmp(path, PATH_ETC_LIBUSER)) {
		FILE *fp = tmpfile();
		assert(fp);
		assert(fputs(!strcmp(path, PATH_SHELLS_FILE) ?
				     "/bin/bash\n" :
				     "UID_MIN 100\nUID_MAX 60000\n",
			     fp) >= 0);
		rewind(fp);
		return fp;
	}
	return __real_fopen(path, mode);
}

int __wrap_stat(const char *path, struct stat *sb);
int __real_stat(const char *path, struct stat *sb);
int __wrap_stat(const char *path, struct stat *sb)
{
	if (!strcmp(path, PATH_EXPORT_HOME)) {
		errno = ENOENT;
		return -1;
	}
	return __real_stat(path, sb);
}

int __wrap_semanage_fcontext_iterate(semanage_handle_t *sh,
				     int (*fn)(const semanage_fcontext_t *,
					       void *),
				     void *arg);
int __wrap_semanage_fcontext_iterate(semanage_handle_t *sh,
				     int (*fn)(const semanage_fcontext_t *,
					       void *),
				     void *arg)
{
	(void)sh;
	(void)fn;
	fc_match_handle_t *match = arg;
	if (iterator_error)
		return STATUS_ERR;
	if (conflict) {
		assert(!strcmp(match->dir, conflict));
		match->matched = 1;
	}
	return 0;
}

int __wrap_sepol_context_check(sepol_handle_t *sh, const sepol_policydb_t *p,
			       const sepol_context_t *c);
int __wrap_sepol_context_check(sepol_handle_t *sh, const sepol_policydb_t *p,
			       const sepol_context_t *c)
{
	(void)sh;
	(void)p;
	(void)c;
	return 0;
}

int __wrap_asprintf(char **out, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));
int __wrap_asprintf(char **out, const char *fmt, ...)
{
	va_list ap;
	int rc;
	if (!strcmp(fmt, "%s%s") && ++rewrite_calls == fail_at) {
		failures++;
		errno = ENOMEM;
		return -1;
	}
	va_start(ap, fmt);
	rc = vasprintf(out, fmt, ap);
	va_end(ap);
	return rc;
}

static void put(const char *path, const char *text)
{
	FILE *fp = fopen(path, "we");
	assert(fp && fputs(text, fp) >= 0 && fclose(fp) == 0);
}

int main(void)
{
	const struct {
		const char *home, *local, *dist, *parent;
	} scenarios[] = {
		{ "/srv/alice", "",
		  "/srv /canonical\n/srv/alice /srv/special\n", "/srv" },
		{ "/srv/alice", "", "", "/srv" },
		{ "/srv/alice/", "", "/srv /canonical\n", "/canonical" },
		{ "/srv/alice", "", "/srv/alice /canonical/alice\n",
		  "/canonical" },
		{ "/srv/team/alice", "", "/srv/* /canonical\n", "/canonical" },
		{ "/srv/team/alice", "", "/srv/*/alice /canonical/alice\n",
		  "/canonical" },
		{ "/srv/alice", "/srv /middle\n", "/middle /canonical\n",
		  "/canonical" },
		{ "/srv/alice", "/srv /middle\n",
		  "/middle/alice /canonical/alice\n", "/canonical" },
		{ "/srv/alice", "",
		  "/srv /canonical\n/srv/alice /special/alice\n", "/special" },
		{ "/srv/alice", "",
		  "/srv/alice /srv/special\n/srv /canonical\n", "/canonical" },
		{ "/srv/alice", "", "/srv/alice /\n", NULL },
		{ "/srv/alice", "", "/srv/alice /alice\n", NULL },
		{ "/srv/alice", "", "/srv/alice relative\n", NULL },
		{ "/", "", "", NULL },
		{ "/alice", "", "", NULL },
	};
	semanage_handle_t sh = { 0 };
	sh.sepolh = sepol_handle_create();
	assert(sh.sepolh);
	unsigned cases = 0;
	for (unsigned i = 0; i < sizeof(scenarios) / sizeof(scenarios[0]);
	     i++) {
		char tmp[] = "/tmp/genhomedircon-parent-XXXXXX";
		char fc[256], local[256], dist[256], key[512];
		assert(mkdtemp(tmp));
		snprintf(fc, sizeof(fc), "%s/fc", tmp);
		snprintf(local, sizeof(local), "%s/fc.subs", tmp);
		snprintf(dist, sizeof(dist), "%s/fc.subs_dist", tmp);
		put(local, scenarios[i].local);
		put(dist, scenarios[i].dist);
		home = scenarios[i].home;
		genhomedircon_settings_t s = { .usepasswd = 1,
					       .h_semanage = &sh };
		assert(semanage_path_subs_load(&sh, local, &s.local_subs) == 0);
		assert(semanage_path_subs_load(&sh, dist, &s.dist_subs) == 0);
		for (unsigned mode = 0; mode < 8; mode++) {
			semanage_list_t *homes = NULL;
			char ignored[256];
			s.usepasswd = mode != 7;
			conflict = mode == 1 ? scenarios[i].parent : NULL;
			iterator_error = mode == 4;
			fail_at = mode == 5 ? 1 : mode == 6 ? 2 : 0;
			rewrite_calls = failures = 0;
			if (mode == 2 || mode == 3) {
				char *canonical = NULL;
				snprintf(ignored, sizeof(ignored), "%s", home);
				size_t len = strlen(ignored);
				while (len > 1 && ignored[len - 1] == '/')
					ignored[--len] = '\0';
				if (mode == 3) {
					assert(semanage_path_subs_canonicalize(
						       s.local_subs,
						       s.dist_subs, ignored,
						       &canonical) == 0);
					if (canonical)
						snprintf(ignored,
							 sizeof(ignored), "%s",
							 canonical);
					free(canonical);
				}
				assert(ignore_setup(ignored) == 0);
			}
			int rc = get_home_dirs(&s, &homes);
			if (failures ||
			    (iterator_error && scenarios[i].parent)) {
				assert(rc == STATUS_ERR && !homes);
			} else {
				assert(rc == STATUS_SUCCESS && homes);
				bool skipped = !scenarios[i].parent ||
					       mode == 1 || mode == 2 ||
					       mode == 3 || mode == 7;
				assert(semanage_list_find(homes, "/home"));
				if (scenarios[i].parent)
					assert(!!semanage_list_find(
						       homes,
						       scenarios[i].parent) ==
					       !skipped);
				for (semanage_list_t *h = homes; h; h = h->next)
					assert(!strcmp(h->data, "/home") ||
					       (scenarios[i].parent &&
						!strcmp(h->data,
							scenarios[i].parent)));
				if (!skipped && mode == 0) {
					FILE *fp = fopen(fc, "we");
					assert(fp);
					char template[] =
						"HOME_ROOT/[^/]+/ssh_key system_u:object_r:ssh_home_t:s0";
					semanage_list_t tpl = {
						.data = template
					};
					for (semanage_list_t *h = homes; h;
					     h = h->next)
						assert(write_home_root_context(
							       &s, fp, &tpl,
							       h->data) ==
						       STATUS_SUCCESS);
					assert(fclose(fp) == 0);
					struct selinux_opt opt = {
						SELABEL_OPT_PATH, fc
					};
					struct selabel_handle *labels =
						selabel_open(SELABEL_CTX_FILE,
							     &opt, 1);
					assert(labels);
					snprintf(key, sizeof(key), "%s/ssh_key",
						 home);
					char *context = NULL;
					assert(selabel_lookup_raw(
						       labels, &context, key,
						       S_IFREG) == 0);
					assert(strstr(context, ":ssh_home_t:"));
					free(context);
					selabel_close(labels);
					assert(unlink(fc) == 0);
				}
				semanage_list_destroy(&homes);
			}
			ignore_free();
			cases++;
		}
		fail_at = 0;
		iterator_error = false;
		conflict = NULL;
		semanage_path_subs_free(&s.local_subs);
		semanage_path_subs_free(&s.dist_subs);
		assert(unlink(local) == 0 && unlink(dist) == 0 &&
		       rmdir(tmp) == 0);
	}
	sepol_handle_destroy(sh.sepolh);
	printf("genhomedircon canonical parent: %u cases passed\n", cases);
	return 0;
}
