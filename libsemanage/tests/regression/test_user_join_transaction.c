/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
#undef NDEBUG
#include <assert.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <selinux/selinux.h>
#include <semanage/semanage.h>

#include "handle.h"
#include "semanage_store.h"

static void write_file(semanage_handle_t *sh, const char *path,
		       const char *data)
{
	char *parent = strdup(path);
	FILE *fp;

	assert(parent);
	assert(semanage_mkpath(sh, dirname(parent)) == 0);
	free(parent);
	fp = fopen(path, "w");
	assert(fp);
	assert(fputs(data, fp) >= 0);
	assert(fclose(fp) == 0);
}

static void set_program(external_prog_t *prog)
{
	assert(prog);
	free(prog->path);
	free(prog->args);
	prog->path = strdup("/bin/true");
	prog->args = strdup("");
	assert(prog->path && prog->args);
}

static void check_user(semanage_handle_t *sh, semanage_user_key_t *key,
		       const char *prefix)
{
	semanage_user_t *user = NULL;
	unsigned int count;
	int exists;

	assert(semanage_user_exists_local(sh, key, &exists) >= 0);
	assert(exists == (prefix != NULL));
	assert(semanage_user_count_local(sh, &count) >= 0);
	assert(count == (prefix ? 1U : 0U));
	if (prefix) {
		assert(semanage_user_query_local(sh, key, &user) >= 0);
		assert(strcmp(semanage_user_get_prefix(user), prefix) == 0);
		assert(semanage_user_has_role(user, "test_r"));
		semanage_user_free(user);
	}
}

static void run_case(int ro, int warm, int operation)
{
	char root[] = "/tmp/semanage-user-join-XXXXXX";
	semanage_handle_t *sh;
	semanage_user_t *user = NULL;
	semanage_user_key_t *key = NULL;
	const char *expected = operation == 2 ? NULL : "updated";
	const char *path;
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
	set_program(sh->conf->sefcontext_compile);
	set_program(sh->conf->setfiles);
	if (ro) {
		assert(sh->conf->n_ro_store_roots == 0);
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
	assert(semanage_disconnect(sh) == 0);

	/* Seed either vendor or writable records; operation 0 tests addition. */
	if (operation != 0) {
		path = ro ? semanage_ro_active_path(0,
						    SEMANAGE_USERS_BASE_LOCAL) :
			    semanage_path(SEMANAGE_ACTIVE,
					  SEMANAGE_USERS_BASE_LOCAL);
		write_file(
			sh, path,
			"user first_u roles { test_r } level s0 range s0;\n");
		path = ro ? semanage_ro_active_path(
				    0, SEMANAGE_USERS_EXTRA_LOCAL) :
			    semanage_path(SEMANAGE_ACTIVE,
					  SEMANAGE_USERS_EXTRA_LOCAL);
		write_file(sh, path, "user first_u prefix original;\n");
	}
	assert(semanage_connect(sh) == 0);
	assert(semanage_user_key_create(sh, "first_u", &key) == 0);
	if (warm)
		check_user(sh, key, operation ? "original" : NULL);
	serial = semanage_direct_get_serial(sh);
	assert(serial >= 0);
	assert(semanage_begin_transaction(sh) == 0);
	assert(semanage_direct_get_serial(sh) == serial);
	if (operation == 2) {
		assert(semanage_user_del_local(sh, key) >= 0);
	} else {
		assert(semanage_user_query(sh, key, &user) >= 0);
		assert(semanage_user_set_prefix(sh, user, expected) == 0);
		assert(semanage_user_modify_local(sh, key, user) >= 0);
		semanage_user_free(user);
	}
	assert(semanage_commit(sh) >= 0);
	assert(semanage_disconnect(sh) == 0);
	assert(semanage_connect(sh) == 0);
	check_user(sh, key, expected);
	semanage_user_key_free(key);
	assert(semanage_disconnect(sh) == 0);
	semanage_handle_destroy(sh);
	assert(semanage_remove_directory(root) == 0);
}

/* Store paths are process-global. Each case runs without touching host policy. */
int main(void)
{
	int ro, warm, operation, status;
	pid_t pid;

	for (ro = 0; ro < 2; ro++) {
		for (warm = 0; warm < 2; warm++) {
			for (operation = 0; operation < 3; operation++) {
				pid = fork();
				assert(pid >= 0);
				if (pid == 0) {
					run_case(ro, warm, operation);
					_exit(0);
				}
				assert(waitpid(pid, &status, 0) == pid);
				assert(WIFEXITED(status) &&
				       WEXITSTATUS(status) == 0);
			}
		}
	}
	puts("User JOIN transaction tests passed.");
	return 0;
}
