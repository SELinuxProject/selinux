/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <glob.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <selinux/selinux.h>

#include "handle.h"
#include "semanage_store.h"

int __real_fsync(int fd);
int __wrap_fsync(int fd);
int __real_rename(const char *from, const char *to);
int __wrap_rename(const char *from, const char *to);
int __real_link(const char *from, const char *to);
int __wrap_link(const char *from, const char *to);
int __real_unlinkat(int fd, const char *path, int flags);
int __wrap_unlinkat(int fd, const char *path, int flags);
int __real_glob(const char *pattern, int flags,
		int (*errfunc)(const char *, int), glob_t *matches);
int __wrap_glob(const char *pattern, int flags,
		int (*errfunc)(const char *, int), glob_t *matches);

static int sweep_mode = -1;
static int sweep_injected;

int __wrap_unlinkat(int fd, const char *path, int flags)
{
	if (sweep_mode >= 0) {
		char proc[64], directory[PATH_MAX];
		assert(snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd) <
		       (int)sizeof(proc));
		ssize_t n = readlink(proc, directory, sizeof(directory) - 1);
		assert(n >= 0);
		directory[n] = '\0';
		/* A sweep must never consume the current transaction's backup. */
		assert(strstr(directory, "/.semanage-backup-stale-"));
		if (sweep_mode == 3 && !sweep_injected &&
		    !strcmp(path, "original")) {
			sweep_injected++;
			errno = EACCES;
			return -1;
		}
	}
	return __real_unlinkat(fd, path, flags);
}

int __wrap_glob(const char *pattern, int flags,
		int (*errfunc)(const char *, int), glob_t *matches)
{
	if (sweep_mode == 4) {
		sweep_injected++;
		return GLOB_NOSPACE;
	}
	return __real_glob(pattern, flags, errfunc, matches);
}

enum fault {
	NONE,
	BACKUP,
	MANIFEST,
	PUBLISH_STORE,
	RESTORE_STORE,
	RESTORE_PREVIOUS,
	RESTORE_FILE,
	RESTORE_LINK,
	RELOAD,
	SYMLINK,
	STAGED_STAT
};
static enum fault fault;
static int injected;
static int manifest_count;
static const char *active_path, *sandbox_path, *previous_path, *restore_path;

static int fail_at;
static int sync_count;

int __wrap_fsync(int fd)
{
	char proc[64], path[PATH_MAX];
	assert(snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd) <
	       (int)sizeof(proc));
	ssize_t n = readlink(proc, path, sizeof(path) - 1);
	assert(n >= 0);
	path[n] = '\0';
	if (strstr(path, "/.semanage-backup-") &&
	    strstr(path, "/destination")) {
		manifest_count++;
		if (fault == MANIFEST && !injected++) {
			errno = ENOSPC;
			return -1;
		}
		return __real_fsync(fd);
	}
	if (++sync_count == fail_at) {
		errno = ENOSPC;
		return -1;
	}
	return __real_fsync(fd);
}

int __wrap_link(const char *from, const char *to)
{
	if (!injected && ((fault == BACKUP && strstr(to, "/original")) ||
			  (fault == RESTORE_LINK && strstr(to, "/restore")))) {
		injected++;
		errno = EIO;
		return -1;
	}
	return __real_link(from, to);
}

int __wrap_rename(const char *from, const char *to)
{
	if (active_path && !injected &&
	    ((fault == PUBLISH_STORE && !strcmp(from, sandbox_path) &&
	      !strcmp(to, active_path)) ||
	     (fault == RESTORE_STORE && !strcmp(from, active_path) &&
	      !strcmp(to, sandbox_path)) ||
	     (fault == RESTORE_PREVIOUS && !strcmp(from, previous_path) &&
	      !strcmp(to, active_path)) ||
	     (fault == RESTORE_FILE && strstr(from, "/restore") &&
	      !strcmp(to, restore_path)))) {
		injected++;
		errno = EIO;
		return -1;
	}
	return __real_rename(from, to);
}

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

static void check_file(const char *path, const char *expected)
{
	char buf[128] = { 0 };
	FILE *fp = fopen(path, "r");

	assert(fp);
	assert(fread(buf, 1, sizeof(buf) - 1, fp) == strlen(expected));
	assert(strcmp(buf, expected) == 0);
	assert(fclose(fp) == 0);
}

static void set_program(external_prog_t *prog, const char *path)
{
	assert(prog);
	free(prog->path);
	free(prog->args);
	prog->path = strdup(path);
	prog->args = strdup("");
	assert(prog->path && prog->args);
}

static int was_absent(int missing, int file)
{
	return missing == 2 ? file == SEMANAGE_KERNEL : missing && !(file % 2);
}

static void run_case(int failure, int missing, int reload_failure)
{
	char root[] = "/tmp/semanage-rollback-XXXXXX";
	struct stat original[SEMANAGE_FINAL_PATH_NUM], current;
	semanage_handle_t *sh;
	const char *path;
	int i, rc;
	int failed = failure || reload_failure;
	int keep = fault == RESTORE_STORE || fault == RESTORE_PREVIOUS ||
		   fault == RESTORE_FILE || fault == RESTORE_LINK ||
		   fault == RELOAD || (reload_failure && missing == 2);
	char loader[PATH_MAX], loaded[PATH_MAX], calls[PATH_MAX],
		script[PATH_MAX * 5];
	char symlink_target[PATH_MAX];
	int xattr_supported = 0;

	assert(mkdtemp(root));
	assert(semanage_set_root(root) == 0);
	sh = semanage_handle_create_with_path("/dev/null");
	assert(sh);
	semanage_select_store(sh, "store", SEMANAGE_CON_DIRECT);
	semanage_set_store_root(sh, "/store");
	sh->conf->relabel_store = 0;
	sh->conf->disable_genhomedircon = 0;
	sh->do_check_contexts = 0;
	sh->do_reload = reload_failure;
	sh->u.direct.activelock_file_fd = -1;
	sh->u.direct.translock_file_fd = -1;
	set_program(sh->conf->sefcontext_compile, "/bin/true");
	set_program(sh->conf->load_policy, "/bin/false");
	assert(semanage_check_init(sh, sh->conf->store_root_path) == 0);
	assert(semanage_create_store(sh, 1) == 0);
	write_file(sh, semanage_path(SEMANAGE_ACTIVE, SEMANAGE_COMMIT_NUM_FILE),
		   "41");
	assert(semanage_make_sandbox(sh) == 0);
	assert(semanage_make_final(sh) == 0);
	active_path = semanage_path(SEMANAGE_ACTIVE, SEMANAGE_TOPLEVEL);
	sandbox_path = semanage_path(SEMANAGE_TMP, SEMANAGE_TOPLEVEL);
	previous_path = semanage_path(SEMANAGE_PREVIOUS, SEMANAGE_TOPLEVEL);
	restore_path = semanage_final_path(SEMANAGE_FINAL_SELINUX, 1);

	for (i = 1; i < SEMANAGE_FINAL_PATH_NUM; i++) {
		path = semanage_final_path(SEMANAGE_FINAL_SELINUX, i);
		if (!was_absent(missing, i)) {
			write_file(sh, path, "old runtime\n");
			assert(chmod(path, 0640) == 0);
			assert(lstat(path, &original[i]) == 0);
		}
		write_file(sh, semanage_final_path(SEMANAGE_FINAL_TMP, i),
			   "new runtime\n");
	}
	if (fault == SYMLINK) {
		assert(snprintf(symlink_target, sizeof(symlink_target),
				"%s/symlink-target",
				root) < (int)sizeof(symlink_target));
		assert(rename(restore_path, symlink_target) == 0);
		assert(symlink(symlink_target, restore_path) == 0);
		assert(lstat(restore_path, &original[1]) == 0);
	} else {
		xattr_supported = setxattr(restore_path, "user.rollback-test",
					   "old", 3, 0) == 0;
	}
	if (fault == STAGED_STAT) {
		path = semanage_final_path(SEMANAGE_FINAL_TMP, SEMANAGE_NC);
		assert(unlink(path) == 0);
		assert(symlink(path, path) == 0);
	}
	if (reload_failure) {
		const char *runtime = semanage_final_path(
			SEMANAGE_FINAL_SELINUX, SEMANAGE_KERNEL);
		assert(snprintf(loader, sizeof(loader), "%s/loader", root) <
		       (int)sizeof(loader));
		assert(snprintf(loaded, sizeof(loaded), "%s/loaded", root) <
		       (int)sizeof(loaded));
		assert(snprintf(calls, sizeof(calls), "%s/calls", root) <
		       (int)sizeof(calls));
		assert(snprintf(script, sizeof(script),
				"#!/bin/sh\n/bin/cp '%s' '%s' || exit 2\n"
				"if [ ! -e '%s' ]; then echo first > '%s'; exit 1; fi\n"
				"echo restored >> '%s'\nexit %d\n",
				runtime, loaded, calls, calls, calls,
				fault == RELOAD ? 1 : 0) < (int)sizeof(script));
		write_file(sh, loader, script);
		assert(chmod(loader, 0700) == 0);
		set_program(sh->conf->load_policy, loader);
	}
	assert(selinux_set_policy_root(semanage_final_path(
		       SEMANAGE_FINAL_SELINUX, SEMANAGE_FINAL_TOPLEVEL)) == 0);
	fail_at = failure;
	sync_count = 0;
	manifest_count = 0;
	rc = semanage_install_sandbox(sh);
	assert(failed ? rc < 0 : rc == 42);
	if (failure && (fault == NONE || fault == SYMLINK ||
			fault == RESTORE_FILE || fault == RESTORE_LINK)) {
		assert(errno == ENOSPC);
		assert(sync_count == failure);
	}
	if (fault == BACKUP || fault == MANIFEST || fault == PUBLISH_STORE ||
	    fault == STAGED_STAT)
		assert(sync_count == 0);
	if (fault == NONE || fault == SYMLINK)
		assert(manifest_count == SEMANAGE_FINAL_PATH_NUM - 1);
	if (fault != NONE && fault != RELOAD && fault != SYMLINK &&
	    fault != STAGED_STAT)
		assert(injected);

	for (i = 1; i < SEMANAGE_FINAL_PATH_NUM; i++) {
		path = semanage_final_path(SEMANAGE_FINAL_SELINUX, i);
		if ((fault == RESTORE_FILE || fault == RESTORE_LINK) &&
		    i == 1) {
			check_file(path, "new runtime\n");
			continue;
		}
		if (failed && was_absent(missing, i)) {
			assert(lstat(path, &current) < 0 && errno == ENOENT);
			continue;
		}
		check_file(path, failed ? "old runtime\n" : "new runtime\n");
		if (failed) {
			assert(lstat(path, &current) == 0);
			assert(current.st_ino == original[i].st_ino);
			assert(current.st_mode == original[i].st_mode);
			assert(current.st_uid == original[i].st_uid &&
			       current.st_gid == original[i].st_gid);
			assert(keep ? current.st_nlink > original[i].st_nlink :
				      current.st_nlink == original[i].st_nlink);
		}
	}
	if (failed && fault != RESTORE_STORE && fault != RESTORE_PREVIOUS)
		check_file(semanage_path(SEMANAGE_ACTIVE,
					 SEMANAGE_COMMIT_NUM_FILE),
			   "41");
	else if (!failed || fault == RESTORE_STORE)
		assert(semanage_direct_get_serial(sh) == 42);
	else
		assert(access(active_path, F_OK) < 0 && errno == ENOENT);
	if (failed && xattr_supported && fault != RESTORE_FILE &&
	    fault != RESTORE_LINK) {
		char value[3];
		assert(getxattr(restore_path, "user.rollback-test", value,
				sizeof(value)) == 3);
		assert(!memcmp(value, "old", 3));
	}
	if (reload_failure) {
		int retry = fault != RESTORE_STORE &&
			    fault != RESTORE_PREVIOUS &&
			    !was_absent(missing, SEMANAGE_KERNEL);
		check_file(calls, retry ? "first\nrestored\n" : "first\n");
		check_file(loaded, retry ? "old runtime\n" : "new runtime\n");
		if (!retry)
			keep = 1;
	}
	unsigned int backups = 0;
	for (i = 1; i < SEMANAGE_FINAL_PATH_NUM; i++) {
		char pattern[PATH_MAX], *parent;
		glob_t matches = { 0 };
		parent = strdup(semanage_final_path(SEMANAGE_FINAL_SELINUX, i));
		assert(parent);
		assert(snprintf(pattern, sizeof(pattern),
				"%s/.semanage-backup-*/destination",
				dirname(parent)) < (int)sizeof(pattern));
		free(parent);
		int grc = glob(pattern, 0, NULL, &matches);
		assert(grc == 0 || grc == GLOB_NOMATCH);
		backups += matches.gl_pathc;
		for (size_t j = 0; j < matches.gl_pathc; j++) {
			char original_path[PATH_MAX], destination[PATH_MAX],
				state[16];
			FILE *fp = fopen(matches.gl_pathv[j], "r");
			assert(fp && fgets(state, sizeof(state), fp) &&
			       fgets(destination, sizeof(destination), fp));
			assert(fclose(fp) == 0);
			destination[strcspn(destination, "\n")] = '\0';
			assert(!strcmp(state, "present\n") ||
			       !strcmp(state, "absent\n"));
			char *dir = strdup(matches.gl_pathv[j]);
			assert(dir);
			assert(snprintf(original_path, sizeof(original_path),
					"%s/original", dirname(dir)) <
			       (int)sizeof(original_path));
			free(dir);
			if (!strcmp(state, "present\n"))
				check_file(original_path, "old runtime\n");
			else
				assert(access(original_path, F_OK) < 0 &&
				       errno == ENOENT);
			if (!strcmp(destination, restore_path) &&
			    (fault == RESTORE_FILE || fault == RESTORE_LINK)) {
				assert(lstat(original_path, &current) == 0);
				assert(current.st_ino == original[1].st_ino);
			}
		}
		globfree(&matches);
	}
	assert(keep ? backups > 0 : backups == 0);
	assert(sh->u.direct.activelock_file_fd == -1);
	if (fault == RESTORE_FILE || fault == RELOAD) {
		/* Exercise a real retained backup followed by successful publication. */
		fault = NONE;
		fail_at = 0;
		sh->do_reload = 0;
		assert(semanage_make_sandbox(sh) == 0);
		assert(semanage_make_final(sh) == 0);
		for (i = 1; i < SEMANAGE_FINAL_PATH_NUM; i++)
			write_file(sh,
				   semanage_final_path(SEMANAGE_FINAL_TMP, i),
				   "retry runtime\n");
		assert(semanage_install_sandbox(sh) == 42);
		for (i = 1; i < SEMANAGE_FINAL_PATH_NUM; i++) {
			char pattern[PATH_MAX], *parent;
			glob_t matches = { 0 };
			parent = strdup(
				semanage_final_path(SEMANAGE_FINAL_SELINUX, i));
			assert(parent);
			assert(snprintf(pattern, sizeof(pattern),
					"%s/.semanage-backup-*",
					dirname(parent)) <
			       (int)sizeof(pattern));
			free(parent);
			assert(glob(pattern, 0, NULL, &matches) ==
			       GLOB_NOMATCH);
			globfree(&matches);
		}
	}
	printf("rollback: fault=%d write=%d absent=%d reload=%d retained=%d passed\n",
	       fault, failure, missing, reload_failure, keep);
	fflush(stdout);
	if (fault == STAGED_STAT)
		assert(unlink(semanage_final_path(SEMANAGE_FINAL_TMP,
						  SEMANAGE_NC)) == 0);
	semanage_handle_destroy(sh);
	assert(semanage_remove_directory(root) == 0);
}

static void stale_backup(semanage_handle_t *sh, const char *directory,
			 const char *state, const char *destination,
			 int original)
{
	char path[PATH_MAX], manifest[PATH_MAX + 32];
	assert(snprintf(path, sizeof(path), "%s/destination", directory) <
	       (int)sizeof(path));
	assert(snprintf(manifest, sizeof(manifest), "%s\n%s\n", state,
			destination) < (int)sizeof(manifest));
	write_file(sh, path, manifest);
	if (original) {
		assert(snprintf(path, sizeof(path), "%s/original", directory) <
		       (int)sizeof(path));
		write_file(sh, path, "stale runtime\n");
	}
}

static void run_sweep_case(int mode)
{
	/* Exercise literal glob metacharacters in the configured path too. */
	char root[] = "/tmp/semanage-sweep-[x]*?\\-XXXXXX";
	char stale[SEMANAGE_FINAL_PATH_NUM][PATH_MAX], extra[6][PATH_MAX];
	char path[PATH_MAX], target[PATH_MAX], *parent;
	semanage_handle_t *sh;
	struct stat sb;
	int rc, remaining = 0;

	assert(mkdtemp(root));
	assert(semanage_set_root(root) == 0);
	sh = semanage_handle_create_with_path("/dev/null");
	assert(sh);
	semanage_select_store(sh, "store", SEMANAGE_CON_DIRECT);
	semanage_set_store_root(sh, "/store");
	sh->conf->relabel_store = 0;
	sh->conf->disable_genhomedircon = 1;
	sh->conf->save_previous = mode % 2;
	sh->do_check_contexts = 0;
	sh->do_reload = 1;
	sh->u.direct.activelock_file_fd = -1;
	sh->u.direct.translock_file_fd = -1;
	set_program(sh->conf->sefcontext_compile, "/bin/true");
	set_program(sh->conf->load_policy,
		    mode == 2 ? "/bin/false" : "/bin/true");
	assert(semanage_check_init(sh, sh->conf->store_root_path) == 0);
	assert(semanage_create_store(sh, 1) == 0);
	write_file(sh, semanage_path(SEMANAGE_ACTIVE, SEMANAGE_COMMIT_NUM_FILE),
		   "41");
	assert(semanage_make_sandbox(sh) == 0);
	assert(semanage_make_final(sh) == 0);
	for (int i = 1; i < SEMANAGE_FINAL_PATH_NUM; i++) {
		const char *dst =
			semanage_final_path(SEMANAGE_FINAL_SELINUX, i);
		write_file(sh, dst, "old runtime\n");
		if (i != SEMANAGE_NC)
			write_file(sh,
				   semanage_final_path(SEMANAGE_FINAL_TMP, i),
				   "new runtime\n");
		parent = strdup(dst);
		assert(parent);
		assert(snprintf(stale[i], sizeof(stale[i]),
				"%s/.semanage-backup-stale-%d", dirname(parent),
				i) < (int)sizeof(stale[i]));
		free(parent);
		stale_backup(sh, stale[i], i % 2 ? "present" : "absent", dst,
			     i % 2);
	}
	const char *dst =
		semanage_final_path(SEMANAGE_FINAL_SELINUX, SEMANAGE_KERNEL);
	parent = strdup(dst);
	assert(parent);
	char *dir = dirname(parent);
	for (int i = 0; i < 6; i++) {
		assert(snprintf(extra[i], sizeof(extra[i]),
				"%s/.semanage-backup-stale-extra-%d", dir,
				i) < (int)sizeof(extra[i]));
		stale_backup(sh, extra[i], i == 1 ? "invalid" : "present",
			     i == 0 ? "/another/destination" : dst, 1);
	}
	free(parent);
	assert(snprintf(path, sizeof(path), "%s/destination", extra[2]) <
	       (int)sizeof(path));
	write_file(sh, path, "present\n");
	assert(snprintf(target, sizeof(target), "%s/target", root) <
	       (int)sizeof(target));
	write_file(sh, target, "symlink target\n");
	assert(snprintf(path, sizeof(path), "%s/original", extra[3]) <
	       (int)sizeof(path));
	assert(unlink(path) == 0 && symlink(target, path) == 0);
	assert(snprintf(path, sizeof(path), "%s/destination", extra[4]) <
	       (int)sizeof(path));
	assert(unlink(path) == 0 && symlink(target, path) == 0);
	assert(snprintf(path, sizeof(path), "%s/destination", extra[5]) <
	       (int)sizeof(path));
	assert(unlink(path) == 0 && mkfifo(path, 0600) == 0);
	assert(selinux_set_policy_root(semanage_final_path(
		       SEMANAGE_FINAL_SELINUX, SEMANAGE_FINAL_TOPLEVEL)) == 0);
	fail_at = mode == 1 ? 2 : 0;
	sweep_mode = mode;
	rc = semanage_install_sandbox(sh);
	sweep_mode = -1;
	assert(mode == 1 || mode == 2 ? rc < 0 : rc == 42);
	assert(sh->u.direct.activelock_file_fd == -1);
	for (int i = 1; i < SEMANAGE_FINAL_PATH_NUM; i++) {
		int keep = mode == 1 || mode == 2 || mode == 4 ||
			   i == SEMANAGE_NC || i == SEMANAGE_FC_HOMEDIRS;
		int exists = lstat(stale[i], &sb) == 0;
		if (!keep && mode == 3)
			remaining += exists;
		else
			assert(exists == keep);
		check_file(semanage_final_path(SEMANAGE_FINAL_SELINUX, i),
			   mode == 1 || mode == 2 || i == SEMANAGE_NC ||
					   i == SEMANAGE_FC_HOMEDIRS ?
				   "old runtime\n" :
				   "new runtime\n");
	}
	assert(mode != 3 || (remaining == 1 && sweep_injected == 1));
	assert(mode != 4 || sweep_injected > 0);
	for (int i = 0; i < 6; i++) {
		int keep = i != 3 || mode == 1 || mode == 2 || mode == 4;
		assert((lstat(extra[i], &sb) == 0) == keep);
	}
	check_file(target, "symlink target\n");
	semanage_handle_destroy(sh);
	assert(semanage_remove_directory(root) == 0);
	printf("backup sweep: mode=%d passed\n", mode);
	fflush(stdout);
}

/* Each child gets fresh process-global store paths. No host policy is loaded. */
static void run_child(int failure, int missing, int reload_failure,
		      enum fault mode)
{
	pid_t pid = fork();
	int status;

	assert(pid >= 0);
	if (pid == 0) {
		fault = mode;
		run_case(failure, missing, reload_failure);
		_exit(0);
	}
	assert(waitpid(pid, &status, 0) == pid);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

int main(void)
{
	int i, missing;

	for (missing = 0; missing < 2; missing++) {
		for (i = 1; i < SEMANAGE_FINAL_PATH_NUM; i++)
			run_child(i, missing, 0, NONE);
		run_child(0, missing, 1, NONE);
		run_child(0, missing, 0, NONE);
	}
	run_child(1, 0, 0, BACKUP);
	run_child(1, 0, 0, MANIFEST);
	run_child(1, 0, 0, PUBLISH_STORE);
	run_child(0, 0, 1, RESTORE_STORE);
	run_child(0, 0, 1, RESTORE_PREVIOUS);
	run_child(2, 0, 0, RESTORE_FILE);
	run_child(2, 0, 0, RESTORE_LINK);
	run_child(0, 0, 1, RELOAD);
	run_child(2, 0, 0, SYMLINK);
	run_child(1, 0, 0, STAGED_STAT);
	run_child(0, 1, 1, RESTORE_STORE);
	run_child(0, 2, 1, NONE);
	for (i = 0; i < 5; i++) {
		pid_t pid = fork();
		int status;
		assert(pid >= 0);
		if (pid == 0) {
			run_sweep_case(i);
			_exit(0);
		}
		assert(waitpid(pid, &status, 0) == pid);
		assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	}
	puts("Final-file rollback tests passed.");
	return 0;
}
