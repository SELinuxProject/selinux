/* Verify cleanup around actual subnet-string allocations. */
#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sepol/debug.h>
#include "ibpkey_internal.h"

static const char *scenario;
static int fail_after = -1;
static int strings;
static int tracking;
static void *allocations[16];
void *__real_malloc(size_t size);
void *__wrap_malloc(size_t size);
void __real_free(void *ptr);
void __wrap_free(void *ptr);

void __wrap_free(void *ptr)
{
	for (size_t i = 0; i < sizeof(allocations) / sizeof(allocations[0]);
	     i++)
		if (allocations[i] == ptr)
			allocations[i] = NULL;
	__real_free(ptr);
}

void *__wrap_malloc(size_t size)
{
	/* Only enable failure after fixture construction. */
	if (fail_after >= 0 && strings++ == fail_after) {
		fail_after = -1;
		errno = ENOMEM;
		return NULL;
	}
	void *ptr = __real_malloc(size);
	if (tracking && ptr) {
		for (size_t i = 0;
		     i < sizeof(allocations) / sizeof(allocations[0]); i++) {
			if (!allocations[i]) {
				allocations[i] = ptr;
				return ptr;
			}
		}
		abort();
	}
	return ptr;
}

int dbase_list(semanage_handle_t *handle, dbase_config_t *config,
	       record_t ***records, unsigned int *count)
{
	(void)config;
	semanage_ibpkey_t **items;
	*count = !strcmp(scenario, "empty")  ? 0 :
		 !strcmp(scenario, "single") ? 1 :
					       3;
	items = calloc(*count, sizeof(*items));
	assert(items || !*count);
	for (unsigned int i = 0; i < *count; i++) {
		assert(semanage_ibpkey_create(handle, &items[i]) == 0);
		semanage_ibpkey_set_subnet_prefix_bytes(
			items[i], !strcmp(scenario, "different") ? i + 1 : 1);
		semanage_ibpkey_set_range(items[i], i * 5 + 1, i * 5 + 5);
	}
	if (!strcmp(scenario, "overlap"))
		semanage_ibpkey_set_range(items[1], 5, 15);
	*records = (record_t **)items;
	tracking = 1;
	if (!strncmp(scenario, "fail", 4)) {
		fail_after = atoi(scenario + 4);
		strings = 0;
	}
	return 0;
}

int main(int argc, char **argv)
{
	semanage_handle_t handle = { 0 };
	assert(argc == 2);
	sepol_debug(0);
	scenario = argv[1];
	int rc = semanage_ibpkey_validate_local(&handle);
	int failure = !strcmp(scenario, "overlap") ||
		      !strncmp(scenario, "fail", 4);
	assert(rc == (failure ? -1 : 0));
	if (!strncmp(scenario, "fail", 4))
		assert(fail_after == -1);
	for (size_t i = 0; i < sizeof(allocations) / sizeof(allocations[0]);
	     i++)
		assert(allocations[i] == NULL);
	printf("%s: validation result=%d\n", scenario, rc);
	return 0;
}
