#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sepol/booleans.h>
#include <sepol/policydb/sidtab.h>

void audit_fault(int kind, int nth);
int audit_fault_hits(void);
int audit_live(void);
void *audit_malloc(size_t size);
void *audit_calloc(size_t n, size_t size);
char *audit_strdup(const char *s);
void audit_free(void *p);
int __real_sepol_sidtab_init(sidtab_t *s);
int __wrap_sepol_sidtab_init(sidtab_t *s);
sepol_handle_t *__real_sepol_handle_create(void);
sepol_handle_t *__wrap_sepol_handle_create(void);
char *__real_strdup(const char *s);
char *__wrap_strdup(const char *s);
int __real_sepol_bool_iterate(sepol_handle_t *, const sepol_policydb_t *,
			      int (*)(const sepol_bool_t *, void *), void *);
int __wrap_sepol_bool_iterate(sepol_handle_t *, const sepol_policydb_t *,
			      int (*)(const sepol_bool_t *, void *), void *);
int __real_sepol_policy_file_create(sepol_policy_file_t **pf);
int __wrap_sepol_policy_file_create(sepol_policy_file_t **pf);
void __real_sepol_policy_file_free(sepol_policy_file_t *pf);
void __wrap_sepol_policy_file_free(sepol_policy_file_t *pf);

static int mode, position, seen, hits, files;
static int iterating, in_callback;
static void *allocations[4096];
static int (*iterator_callback)(const sepol_bool_t *, void *);

void audit_fault(int kind, int nth)
{
	mode = kind;
	position = nth;
	seen = hits = 0;
}

int audit_fault_hits(void)
{
	return hits;
}

int audit_live(void)
{
	int n = files;
	for (size_t i = 0; i < 4096; i++)
		n += allocations[i] != NULL;
	return n;
}

static int fail(int kind)
{
	if (mode == kind && ++seen == position) {
		hits++;
		errno = ENOMEM;
		return 1;
	}
	return 0;
}

static void *track(void *p)
{
	if (!p)
		return NULL;
	for (size_t i = 0; i < 4096; i++) {
		if (!allocations[i]) {
			allocations[i] = p;
			return p;
		}
	}
	abort();
}

void *audit_malloc(size_t size)
{
	return fail(1) ? NULL : track(malloc(size));
}

char *audit_strdup(const char *s)
{
	return fail(2) ? NULL : track(strdup(s));
}

void *audit_calloc(size_t n, size_t size)
{
	return fail(5) ? NULL : track(calloc(n, size));
}

void audit_free(void *p)
{
	for (size_t i = 0; i < 4096; i++)
		if (allocations[i] == p)
			allocations[i] = NULL;
	free(p);
}

int __wrap_sepol_sidtab_init(sidtab_t *s)
{
	return fail(6) ? -ENOMEM : __real_sepol_sidtab_init(s);
}

sepol_handle_t *__wrap_sepol_handle_create(void)
{
	return fail(7) ? NULL : __real_sepol_handle_create();
}

char *__wrap_strdup(const char *s)
{
	if (iterating && !in_callback && fail(4))
		return NULL;
	return __real_strdup(s);
}

static int callback(const sepol_bool_t *b, void *arg)
{
	in_callback = 1;
	int rc = iterator_callback(b, arg);
	in_callback = 0;
	return rc;
}

int __wrap_sepol_bool_iterate(sepol_handle_t *h, const sepol_policydb_t *p,
			      int (*fn)(const sepol_bool_t *, void *),
			      void *arg)
{
	iterator_callback = fn;
	iterating = 1;
	int rc = __real_sepol_bool_iterate(h, p, callback, arg);
	iterating = 0;
	return rc;
}

int __wrap_sepol_policy_file_create(sepol_policy_file_t **pf)
{
	int rc = __real_sepol_policy_file_create(pf);
	if (!rc)
		files++;
	return rc;
}

void __wrap_sepol_policy_file_free(sepol_policy_file_t *pf)
{
	if (pf)
		files--;
	__real_sepol_policy_file_free(pf);
}
