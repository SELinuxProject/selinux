#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <sepol/policydb/avrule_block.h>
#include <sepol/policydb/policydb.h>

int main(void)
{
	policydb_t p = { 0 };
	avrule_decl_t decls[3] = { 0 };
	avrule_decl_t *index[] = { &decls[0], &decls[1], &decls[2] };
	uint32_t ids[3];
	scope_datum_t scope = { .scope = SCOPE_DECL,
				.decl_ids = ids,
				.decl_ids_len = 3 };
	type_datum_t type = { .s.value = 1, .primary = 1 };
	char name[] = "test_type";
	const uint32_t orders[][3] = { { 1, 2, 3 }, { 1, 3, 2 }, { 2, 1, 3 },
				       { 2, 3, 1 }, { 3, 1, 2 }, { 3, 2, 1 } };
	unsigned int cases = 0;

	assert(symtab_init(&p.scope[SYM_TYPES], 16) == 0);
	assert(symtab_init(&p.p_types, 16) == 0);
	assert(hashtab_insert(p.scope[SYM_TYPES].table, name, &scope) == 0);
	assert(hashtab_insert(p.p_types.table, name, &type) == 0);
	p.decl_val_to_struct = index;
	/* Types, attributes, and aliases use the declared bitmap, not merely
	 * the presence of an enabled block in the mixed scope list. */
	for (unsigned int flavor = TYPE_TYPE; flavor <= TYPE_ALIAS; flavor++) {
		type.flavor = flavor;
		for (unsigned int enabled = 0; enabled < 8; enabled++)
			for (unsigned int declared = 0; declared < 8;
			     declared++) {
				for (unsigned int i = 0; i < 3; i++) {
					decls[i].enabled =
						!!(enabled & (1U << i));
					assert(ebitmap_set_bit(
						       &decls[i].declared
								.scope[SYM_TYPES],
						       0,
						       !!(declared &
							  (1U << i))) == 0);
				}
				for (unsigned int order = 0; order < 6;
				     order++) {
					for (unsigned int i = 0; i < 3; i++)
						ids[i] = orders[order][i];
					scope.scope = SCOPE_DECL;
					assert(is_id_enabled(name, &p,
							     SYM_TYPES) ==
					       !!(enabled & declared));
					scope.scope = SCOPE_REQ;
					assert(is_id_enabled(name, &p,
							     SYM_TYPES) == 0);
					cases += 2;
				}
			}
	}
	scope.scope = SCOPE_DECL;
	for (unsigned int i = 0; i < 3; i++)
		index[i] = NULL;
	assert(is_id_enabled(name, &p, SYM_TYPES) == 0);
	scope.decl_ids_len = 0;
	assert(is_id_enabled(name, &p, SYM_TYPES) == 0);
	assert(is_id_enabled("missing", &p, SYM_TYPES) == 0);
	for (unsigned int i = 0; i < 3; i++)
		ebitmap_destroy(&decls[i].declared.scope[SYM_TYPES]);
	hashtab_destroy(p.scope[SYM_TYPES].table);
	hashtab_destroy(p.p_types.table);
	printf("PASS %u type enablement checks\n", cases + 3);
	return 0;
}
