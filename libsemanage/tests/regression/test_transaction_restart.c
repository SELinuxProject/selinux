/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
#undef NDEBUG
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <selinux/selinux.h>
#include <semanage/semanage.h>

#include "handle.h"
#include "semanage_store.h"

static const char *fail_scan;

int __real_scandir(const char *path, struct dirent ***entries,
		   int (*filter)(const struct dirent *),
		   int (*compare)(const struct dirent **,
				  const struct dirent **));
int __wrap_scandir(const char *path, struct dirent ***entries,
		   int (*filter)(const struct dirent *),
		   int (*compare)(const struct dirent **,
				  const struct dirent **));

int __wrap_scandir(const char *path, struct dirent ***entries,
		   int (*filter)(const struct dirent *),
		   int (*compare)(const struct dirent **,
				  const struct dirent **))
{
	if (fail_scan && !strcmp(path, fail_scan)) {
		fail_scan = NULL;
		errno = EIO;
		return -1;
	}
	return __real_scandir(path, entries, filter, compare);
}

static void set_program(external_prog_t *prog)
{
	free(prog->path);
	free(prog->args);
	prog->path = strdup("/bin/true");
	prog->args = strdup("");
	assert(prog->path && prog->args);
}

static void check_missing(const char *path)
{
	struct stat st;
	assert(lstat(path, &st) < 0 && errno == ENOENT);
}

static void check_local(semanage_handle_t *sh, semanage_user_key_t *key,
			const char *prefix)
{
	semanage_user_t *user = NULL;
	int exists;
	assert(semanage_user_exists_local(sh, key, &exists) >= 0);
	assert(exists == (prefix != NULL));
	if (!prefix)
		return;
	assert(semanage_user_query_local(sh, key, &user) >= 0);
	assert(!strcmp(semanage_user_get_prefix(user), prefix));
	semanage_user_free(user);
}

static void run_case(int ro, int commit)
{
	char root[] = "/tmp/semanage-restart-XXXXXX";
	char blocker[4096];
	semanage_handle_t *sh;
	semanage_user_t *user = NULL;
	semanage_user_key_t *key = NULL;
	const char *tmp, *final, *flag;
	FILE *fp;
	int serial;

	assert(mkdtemp(root));
	assert(semanage_set_root(root) == 0);
	sh = semanage_handle_create_with_path("/dev/null");
	assert(sh);
	semanage_select_store(sh, "store", SEMANAGE_CON_DIRECT);
	semanage_set_store_root(sh, "/store");
	semanage_set_create_store(sh, 1);
	semanage_set_reload(sh, 0);
	sh->conf->relabel_store = 0;
	sh->conf->disable_genhomedircon = 1;
	sh->do_check_contexts = 0;
	set_program(sh->conf->setfiles);
	set_program(sh->conf->sefcontext_compile);
	if (ro) {
		sh->conf->ro_store_root_paths = calloc(1, sizeof(char *));
		assert(sh->conf->ro_store_root_paths);
		sh->conf->ro_store_root_paths[0] = strdup("/vendor");
		assert(sh->conf->ro_store_root_paths[0]);
		sh->conf->n_ro_store_roots = 1;
	}
	assert(semanage_connect(sh) == 0);
	assert(selinux_set_policy_root(semanage_final_path(
		       SEMANAGE_FINAL_SELINUX, SEMANAGE_FINAL_TOPLEVEL)) == 0);
	assert(semanage_module_install_file(sh, "regression/user_join.cil") >=
	       0);
	assert(semanage_commit(sh) >= 0);
	serial = semanage_direct_get_serial(sh);
	assert(serial >= 0);
	assert(semanage_user_key_create(sh, "first_u", &key) == 0);
	assert(semanage_begin_transaction(sh) == 0);
	assert(semanage_user_query(sh, key, &user) >= 0);
	assert(semanage_user_set_prefix(sh, user, "abandoned") == 0);
	assert(semanage_user_modify_local(sh, key, user) >= 0);
	tmp = semanage_path(SEMANAGE_TMP, SEMANAGE_TOPLEVEL);
	final = semanage_final_path(SEMANAGE_FINAL_TMP,
				    SEMANAGE_FINAL_TOPLEVEL);
	flag = semanage_path(SEMANAGE_TMP, SEMANAGE_DISABLE_DONTAUDIT);
	assert(mkdir(flag, 0700) == 0);
	assert(snprintf(blocker, sizeof(blocker), "%s/keep", flag) <
	       (int)sizeof(blocker));
	fp = fopen(blocker, "w");
	assert(fp && fclose(fp) == 0);
	assert(semanage_commit(sh) < 0);
	assert(sh->commit_err < 0 && !sh->is_in_transaction);
	assert(semanage_direct_get_serial(sh) == serial);
	assert(access(tmp, F_OK) == 0 && access(final, F_OK) == 0);

	/* Failed setup must retain error state and release the transaction lock. */
	fail_scan = final;
	assert(semanage_begin_transaction(sh) < 0);
	assert(!fail_scan && errno == EIO);
	assert(!sh->is_in_transaction && sh->commit_err < 0);
	assert(sh->u.direct.translock_file_fd == -1);

	assert(semanage_begin_transaction(sh) == 0);
	assert(sh->commit_err == 0);
	check_local(sh, key, NULL);
	assert(semanage_user_set_prefix(sh, user, "fresh") == 0);
	assert(semanage_user_modify_local(sh, key, user) >= 0);
	semanage_user_free(user);
	if (commit)
		assert(semanage_commit(sh) >= 0);
	assert(semanage_disconnect(sh) == 0);
	check_missing(tmp);
	check_missing(final);
	assert(semanage_connect(sh) == 0);
	check_local(sh, key, commit ? "fresh" : NULL);
	assert(semanage_disconnect(sh) == 0);
	semanage_user_key_free(key);
	semanage_handle_destroy(sh);
	assert(semanage_remove_directory(root) == 0);
}

int main(void)
{
	int ro, commit, status;
	pid_t child;

	for (ro = 0; ro < 2; ro++) {
		for (commit = 0; commit < 2; commit++) {
			child = fork();
			assert(child >= 0);
			if (!child) {
				run_case(ro, commit);
				_exit(0);
			}
			assert(waitpid(child, &status, 0) == child);
			assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
		}
	}
	puts("Transaction restart and final-directory cleanup tests passed.");
	return 0;
}
