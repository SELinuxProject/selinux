#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sepol/cil/cil.h>
#include <sepol/policydb/conditional.h>
#include <sepol/policydb/policydb.h>

#include "../../src/policydb_validate.h"

static void check_count(unsigned int count)
{
	const char *base =
		"(handleunknown deny) (mls false) "
		"(sid kernel) (sidorder (kernel)) "
		"(sensitivity s0) (sensitivityorder (s0)) "
		"(user system_u) (role test_r) (type test_t) "
		"(userrole system_u test_r) (roletype test_r test_t) "
		"(userlevel system_u (s0)) (userrange system_u ((s0) (s0))) "
		"(sidcontext kernel (system_u test_r test_t ((s0) (s0)))) "
		"(class file (read write)) (classorder (file)) "
		"(allow test_t self (file (read))) ";
	char text[8192], expr[2048], next[2048];
	cil_db_t *db;
	sepol_policydb_t *compiled, *loaded;
	cond_node_t *cond;
	cond_expr_t *last_bool = NULL;
	void *image;
	size_t image_len, used;
	unsigned int i, slot;
	uint32_t saved;
	int n;

	assert(count > 0);
	used = strlen(base);
	memcpy(text, base, used + 1);
	strcpy(expr, "b1");
	for (i = 1; i <= count; i++) {
		n = snprintf(text + used, sizeof(text) - used,
			     "(boolean b%u false) ", i);
		assert(n > 0 && (size_t)n < sizeof(text) - used);
		used += n;
		if (i > 1) {
			n = snprintf(next, sizeof(next), "(or %s b%u)", expr,
				     i);
			assert(n > 0 && (size_t)n < sizeof(next));
			memcpy(expr, next, (size_t)n + 1);
		}
	}
	n = snprintf(text + used, sizeof(text) - used,
		     "(booleanif %s (true (allow test_t self (file (write)))))",
		     expr);
	assert(n > 0 && (size_t)n < sizeof(text) - used);
	used += n;
	cil_db_init(&db);
	assert(cil_add_file(db, "conditional-count.cil", text, used) == 0);
	assert(cil_compile(db) == 0);
	assert(cil_build_policydb(db, &compiled) == 0);
	assert(compiled->p.cond_list->nbools == count);
	assert(sepol_policydb_to_image(NULL, compiled, &image, &image_len) ==
	       0);
	assert(sepol_policydb_create(&loaded) == 0);
	assert(sepol_policydb_from_image(NULL, image, image_len, loaded) == 0);
	free(image);

	/* Rebuild the derived cache on a reader-shaped policydb. */
	cond = loaded->p.cond_list;
	assert(cond && !cond->next && cond->nbools == 0);
	assert(cond_normalize_expr(&loaded->p, cond) == 0);
	assert(cond->nbools == count);
	assert(policydb_validate(NULL, &loaded->p) == 0);
	for (i = 0; i < count; i++) {
		assert(cond_evaluate_expr(&loaded->p, cond->expr) == 0);
		loaded->p.bool_val_to_struct[i]->state = 1;
		assert(cond_evaluate_expr(&loaded->p, cond->expr) == 1);
		loaded->p.bool_val_to_struct[i]->state = 0;
	}

	slot = count < COND_MAX_BOOLS ? count - 1 : COND_MAX_BOOLS - 1;
	saved = cond->bool_ids[slot];
	cond->bool_ids[slot] = 0;
	assert(policydb_validate(NULL, &loaded->p) == -1);
	cond->bool_ids[slot] = count + 1;
	assert(policydb_validate(NULL, &loaded->p) == -1);
	cond->bool_ids[slot] = saved;

	for (cond_expr_t *e = cond->expr; e; e = e->next) {
		if (e->expr_type == COND_BOOL)
			last_bool = e;
	}
	assert(last_bool);
	saved = last_bool->boolean;
	last_bool->boolean = 0;
	assert(policydb_validate(NULL, &loaded->p) == -1);
	last_bool->boolean = count + 1;
	assert(policydb_validate(NULL, &loaded->p) == -1);
	last_bool->boolean = saved;
	assert(policydb_validate(NULL, &loaded->p) == 0);

	sepol_policydb_free(loaded);
	sepol_policydb_free(compiled);
	cil_db_destroy(&db);
}

int main(void)
{
	const unsigned int counts[] = { 1, 4, 5, 6, 8 };

	for (size_t i = 0; i < sizeof(counts) / sizeof(counts[0]); i++)
		check_count(counts[i]);
	puts("conditional count: 5 sizes and 20 invalid-ID controls passed");
	return 0;
}
