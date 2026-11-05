#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <selinux/context.h>
#include <selinux/get_context_list.h>
#include <selinux/selinux.h>

int __wrap_getcon(char **con);
int __wrap_security_check_context(const char *con);
context_t __wrap_context_new(const char *str);
context_t __real_context_new(const char *str);
int __wrap_context_range_set(context_t con, const char *range);
int __real_context_range_set(context_t con, const char *range);
char *__wrap_context_to_str(context_t con);
char *__real_context_to_str(context_t con);

static const char *current_context;
static const char *expected_range;
static unsigned int getcon_calls, failsafe_checks, cases;
static int config_mode, validation_mode, fault, fault_hit;

int __wrap_getcon(char **con)
{
	getcon_calls++;
	*con = strdup(current_context);
	return *con ? 0 : -1;
}

int __wrap_security_check_context(const char *str)
{
	context_t con = __real_context_new(str);
	int failsafe;

	assert(con);
	failsafe = !strcmp(context_type_get(con), "failsafe_t");
	if (failsafe) {
		failsafe_checks++;
		assert(!strcmp(context_range_get(con), expected_range));
	}
	context_free(con);
	if (failsafe && validation_mode) {
		errno = validation_mode == 1 ? EINVAL : ENOENT;
		return -1;
	}
	if (!failsafe && config_mode == 3) {
		errno = EINVAL;
		return -1;
	}
	return 0;
}

context_t __wrap_context_new(const char *str)
{
	if (fault == 1 && strstr(str, ":failsafe_t:")) {
		fault_hit++;
		errno = ENOMEM;
		return NULL;
	}
	return __real_context_new(str);
}

int __wrap_context_range_set(context_t con, const char *range)
{
	if (fault == 2 && !strcmp(context_type_get(con), "failsafe_t")) {
		fault_hit++;
		errno = ENOMEM;
		return -1;
	}
	return __real_context_range_set(con, range);
}

char *__wrap_context_to_str(context_t con)
{
	if (fault == 3 && !strcmp(context_type_get(con), "failsafe_t")) {
		fault_hit++;
		errno = ENOMEM;
		return NULL;
	}
	return __real_context_to_str(con);
}

static void put_file(const char *path, const char *text)
{
	FILE *fp = fopen(path, "w");

	assert(fp);
	assert(fputs(text, fp) >= 0);
	assert(fclose(fp) == 0);
}

static void check_result(const char *str, int fallback)
{
	context_t con = __real_context_new(str);

	assert(con);
	assert(!strcmp(context_user_get(con), "test_u"));
	assert(!strcmp(context_role_get(con), "session_r"));
	assert(!strcmp(context_range_get(con), expected_range));
	assert((strcmp(context_type_get(con), "failsafe_t") == 0) == fallback);
	context_free(con);
}

static void run_case(int api, const char *level, const char *from, int fallback)
{
	char *sentinel = (char *)&cases;
	char *one = sentinel;
	char **list = (char **)&cases;
	int rc, failure = fallback && (validation_mode == 1 || fault);

	getcon_calls = failsafe_checks = fault_hit = 0;
	if (api == 0)
		rc = get_ordered_context_list_with_level("test_u", level, from,
							 &list);
	else if (api == 1)
		rc = get_default_context_with_level("test_u", level, from,
						    &one);
	else
		rc = get_default_context_with_rolelevel("test_u", "session_r",
							level, from, &one);
	assert(getcon_calls == (from == NULL));
	assert(fault_hit == (fault != 0));
	assert(failsafe_checks == (unsigned int)(fallback && !fault));
	if (failure) {
		assert(rc == -1);
		assert(one == sentinel && list == (char **)&cases);
	} else if (api == 0) {
		assert(rc == (fallback ? 1 : 2));
		for (int i = 0; i < rc; i++)
			check_result(list[i], fallback);
		assert(list[rc] == NULL);
		freeconary(list);
	} else {
		assert(rc == 0);
		check_result(one, fallback);
		freecon(one);
	}
	cases++;
}

int main(void)
{
	char root[] = "/tmp/selinux-context-level-XXXXXX";
	char contexts[256], users[256], user[256], defaults[256], failsafe[256];
	const char *entries =
		"source_r:source_t:s0 session_r:normal_t:s0 session_r:other_t:s0\n";

	assert(mkdtemp(root));
	assert(snprintf(contexts, sizeof(contexts), "%s/contexts", root) > 0);
	assert(snprintf(users, sizeof(users), "%s/contexts/users", root) > 0);
	assert(snprintf(user, sizeof(user), "%s/contexts/users/test_u", root) >
	       0);
	assert(snprintf(defaults, sizeof(defaults),
			"%s/contexts/default_contexts", root) > 0);
	assert(snprintf(failsafe, sizeof(failsafe),
			"%s/contexts/failsafe_context", root) > 0);
	assert(mkdir(contexts, 0700) == 0);
	assert(mkdir(users, 0700) == 0);
	assert(selinux_set_policy_root(root) == 0);
	put_file(failsafe, "session_r:failsafe_t:s0\n");

	for (config_mode = 0; config_mode < 4; config_mode++) {
		put_file(user, config_mode == 0 ? entries : "");
		put_file(defaults,
			 config_mode == 1 || config_mode == 3 ? entries : "");
		for (int api = 0; api < 3; api++)
			for (int source = 0; source < 4; source++)
				for (int leveled = 0; leveled < 2; leveled++)
					for (validation_mode = 0;
					     validation_mode < 3;
					     validation_mode++) {
						int fallback = source >= 2 ||
							       config_mode >= 2;
						current_context =
							source < 2 ?
								"old_u:source_r:source_t:s0:c2" :
								"old_u:unmatched_r:unmatched_t:s0:c2";
						expected_range =
							leveled ?
								"s0:c7" :
								(fallback ?
									 "s0" :
									 "s0:c2");
						run_case(
							api,
							leveled ? "s0:c7" :
								  NULL,
							source % 2 ?
								NULL :
								current_context,
							fallback);
					}
	}

	config_mode = 2;
	validation_mode = 0;
	current_context = "old_u:unmatched_r:unmatched_t:s0:c2";
	expected_range = "s0:c7";
	for (int api = 0; api < 3; api++)
		for (int failure = 1; failure <= 3; failure++) {
			fault = failure;
			run_case(api, "s0:c7", NULL, 1);
			fault = 0;
			run_case(api, "s0:c7", NULL, 1);
		}

	assert(unlink(user) == 0);
	assert(unlink(defaults) == 0);
	for (int api = 0; api < 3; api++)
		run_case(api, "s0:c7", NULL, 1);
	assert(unlink(failsafe) == 0);
	assert(rmdir(users) == 0);
	assert(rmdir(contexts) == 0);
	assert(rmdir(root) == 0);
	printf("PASS %u context-level cases\n", cases);
	return 0;
}
