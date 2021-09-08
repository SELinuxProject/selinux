
#include <sepol/policydb/conditional.h>
#include <sepol/policydb/ebitmap.h>
#include <sepol/policydb/policydb.h>

#include "debug.h"
#include "policydb_validate.h"

typedef struct validate {
	uint32_t nprim;
	ebitmap_t gaps;
} validate_t;


static int create_gap_ebitmap(char **val_to_name, uint32_t nprim, ebitmap_t *gaps)
{
	unsigned int i;

	ebitmap_init(gaps);

	for (i = 0; i < nprim; i++) {
		if (!val_to_name[i]) {
			if (ebitmap_set_bit(gaps, i, 1))
				return -1;
		}
	}

	return 0;
}

static int validate_init(validate_t *flavor, char **val_to_name, uint32_t nprim)
{
	flavor->nprim = nprim;
	if (create_gap_ebitmap(val_to_name, nprim, &flavor->gaps))
		return -1;

	return 0;
}

static int validate_array_init(policydb_t *p, validate_t flavors[])
{
	if (validate_init(&flavors[SYM_CLASSES], p->p_class_val_to_name, p->p_classes.nprim))
		goto bad;
	if (validate_init(&flavors[SYM_ROLES], p->p_role_val_to_name, p->p_roles.nprim))
		goto bad;
	if (p->policyvers < POLICYDB_VERSION_AVTAB || p->policyvers > POLICYDB_VERSION_PERMISSIVE) {
		if (validate_init(&flavors[SYM_TYPES], p->p_type_val_to_name, p->p_types.nprim))
			goto bad;
	} else {
		/*
		 * For policy versions between 20 and 23, attributes exist in the policy,
		 * but they only exist in the type_attr_map, so there will be references
		 * to gaps and we just have to treat this case as if there were no gaps.
		 */
		flavors[SYM_TYPES].nprim = p->p_types.nprim;
		ebitmap_init(&flavors[SYM_TYPES].gaps);
	}
	if (validate_init(&flavors[SYM_USERS], p->p_user_val_to_name, p->p_users.nprim))
		goto bad;
	if (validate_init(&flavors[SYM_BOOLS], p->p_bool_val_to_name, p->p_bools.nprim))
		goto bad;
	if (validate_init(&flavors[SYM_LEVELS], p->p_sens_val_to_name, p->p_levels.nprim))
		goto bad;
	if (validate_init(&flavors[SYM_CATS], p->p_cat_val_to_name, p->p_cats.nprim))
		goto bad;

	return 0;

bad:
	return -1;
}

/*
 * Functions to validate both kernel and module policydbs
 */

int value_isvalid(uint32_t value, uint32_t nprim)
{
	if (!value || value > nprim)
		return 0;

	return 1;
}

static int validate_value(uint32_t value, validate_t *flavor)
{
	if (!value || value > flavor->nprim)
		goto bad;
	if (ebitmap_get_bit(&flavor->gaps, value-1))
		goto bad;

	return 0;

bad:
	return -1;
}

static int validate_ebitmap(ebitmap_t *map, validate_t *flavor)
{
	if (ebitmap_length(map) > 0 && ebitmap_highest_set_bit(map) >= flavor->nprim)
		goto bad;
	if (ebitmap_match_any(map, &flavor->gaps))
		goto bad;

	return 0;

bad:
	return -1;
}

static int validate_type_set(type_set_t *type_set, validate_t *type)
{
	if (validate_ebitmap(&type_set->types, type))
		goto bad;
	if (validate_ebitmap(&type_set->negset, type))
		goto bad;

	return 0;

bad:
	return -1;
}

static int validate_role_set(role_set_t *role_set, validate_t *role)
{
	if (validate_ebitmap(&role_set->roles, role))
		return -1;

	return 0;
}

static int validate_scope(__attribute__ ((unused)) hashtab_key_t k, hashtab_datum_t d, void *args)
{
	scope_datum_t *scope_datum = (scope_datum_t *)d;
	uint32_t *nprim = (uint32_t *)args;
	unsigned int i;

	for (i = 0; i < scope_datum->decl_ids_len; i++) {
		if (!value_isvalid(scope_datum->decl_ids[i], *nprim))
			return -1;
	}

	return 0;
}

static int validate_scopes(sepol_handle_t *handle, symtab_t scopes[], avrule_block_t *block)
{
	avrule_decl_t *decl;
	unsigned int i;
	unsigned int num_decls = 0;

	for (; block != NULL; block = block->next) {
		for (decl = block->branch_list; decl; decl = decl->next) {
			num_decls++;
		}
	}

	for (i = 0; i < SYM_NUM; i++) {
		if (hashtab_map(scopes[i].table, validate_scope, &num_decls))
			goto bad;
	}

	return 0;

bad:
	ERR(handle, "Invalid scope");
	return -1;
}

static int validate_constraint_nodes(sepol_handle_t *handle, constraint_node_t *cons, validate_t flavors[])
{
	constraint_expr_t *cexp;

	for (; cons; cons = cons->next) {
		for (cexp = cons->expr; cexp; cexp = cexp->next) {
			if (cexp->attr & CEXPR_USER) {
				if (validate_ebitmap(&cexp->names, &flavors[SYM_USERS]))
					goto bad;
			} else if (cexp->attr & CEXPR_ROLE) {
				if (validate_ebitmap(&cexp->names, &flavors[SYM_ROLES]))
					goto bad;
			} else if (cexp->attr & CEXPR_TYPE) {
				if (validate_ebitmap(&cexp->names, &flavors[SYM_TYPES]))
					goto bad;
				if (validate_type_set(cexp->type_names, &flavors[SYM_TYPES]))
					goto bad;
			}
		}
	}

	return 0;

bad:
	ERR(handle, "Invalid constraint expr");
	return -1;
}

static int validate_class_datum(sepol_handle_t *handle, class_datum_t *class, validate_t flavors[])
{
	if (validate_value(class->s.value, &flavors[SYM_CLASSES]))
		goto bad;
	if (validate_constraint_nodes(handle, class->constraints, flavors))
		goto bad;
	if (validate_constraint_nodes(handle, class->validatetrans, flavors))
		goto bad;

	return 0;

bad:
	ERR(handle, "Invalid class datum");
	return -1;
}

static int validate_role_datum(sepol_handle_t *handle, role_datum_t *role, validate_t flavors[])
{
	if (validate_value(role->s.value, &flavors[SYM_ROLES]))
		goto bad;
	if (validate_ebitmap(&role->dominates, &flavors[SYM_ROLES]))
		goto bad;
	if (validate_type_set(&role->types, &flavors[SYM_TYPES]))
		goto bad;
	if (role->bounds && validate_value(role->bounds, &flavors[SYM_ROLES]))
		goto bad;
	if (validate_ebitmap(&role->roles, &flavors[SYM_ROLES]))
		goto bad;

	return 0;

bad:
	ERR(handle, "Invalid class datum");
	return -1;
}

static int validate_type_datum(sepol_handle_t *handle, type_datum_t *type, validate_t flavors[])
{
	if (validate_value(type->s.value, &flavors[SYM_TYPES]))
		goto bad;
	if (validate_ebitmap(&type->types, &flavors[SYM_TYPES]))
		goto bad;
	if (type->bounds && validate_value(type->bounds, &flavors[SYM_TYPES]))
		goto bad;

	return 0;

bad:
	ERR(handle, "Invalid type datum");
	return -1;
}

static int validate_mls_semantic_cat(mls_semantic_cat_t *cat, validate_t *cats)
{
	for (; cat; cat = cat->next) {
		if (validate_value(cat->low, cats))
			goto bad;
		if (validate_value(cat->high, cats))
			goto bad;
	}

	return 0;

bad:
	return -1;
}

static int validate_mls_semantic_level(mls_semantic_level_t *level, validate_t *sens, validate_t *cats)
{
	if (level->sens == 0)
		return 0;
	if (validate_value(level->sens, sens))
		goto bad;
	if (validate_mls_semantic_cat(level->cat, cats))
		goto bad;

	return 0;

bad:
	return -1;
}

static int validate_mls_semantic_range(mls_semantic_range_t *range, validate_t *sens, validate_t *cats)
{
	if (validate_mls_semantic_level(&range->level[0], sens, cats))
		goto bad;
	if (validate_mls_semantic_level(&range->level[1], sens, cats))
		goto bad;

	return 0;

bad:
	return -1;
}

static int validate_user_datum(sepol_handle_t *handle, user_datum_t *user, validate_t flavors[])
{
	if (validate_value(user->s.value, &flavors[SYM_USERS]))
		goto bad;
	if (validate_role_set(&user->roles, &flavors[SYM_ROLES]))
		goto bad;
	if (validate_mls_semantic_range(&user->range, &flavors[SYM_LEVELS], &flavors[SYM_CATS]))
		goto bad;
	if (validate_mls_semantic_level(&user->dfltlevel, &flavors[SYM_LEVELS], &flavors[SYM_CATS]))
		goto bad;
	if (user->bounds && validate_value(user->bounds, &flavors[SYM_USERS]))
		goto bad;

	return 0;

bad:
	ERR(handle, "Invalid user datum");
	return -1;
}

static int validate_datum_arrays(sepol_handle_t *handle, policydb_t *p, validate_t flavors[])
{
	unsigned int i;

	for (i = 0; i < p->p_classes.nprim; i++) {
		if (p->class_val_to_struct[i]) {
			if (ebitmap_get_bit(&flavors[SYM_CLASSES].gaps, i))
				goto bad;
			if (validate_class_datum(handle, p->class_val_to_struct[i], flavors))
				goto bad;
		} else {
			if (!ebitmap_get_bit(&flavors[SYM_CLASSES].gaps, i))
				goto bad;
		}
	}

	for (i = 0; i < p->p_roles.nprim; i++) {
		if (p->role_val_to_struct[i]) {
			if (ebitmap_get_bit(&flavors[SYM_ROLES].gaps, i))
				goto bad;
			if (validate_role_datum(handle, p->role_val_to_struct[i], flavors))
				goto bad;
		} else {
			if (!ebitmap_get_bit(&flavors[SYM_ROLES].gaps, i))
				goto bad;
		}
	}

	/*
	 * For policy versions between 20 and 23, attributes exist in the policy,
	 * but only in the type_attr_map, so all gaps must be assumed to be valid.
	 */
	if (p->policyvers < POLICYDB_VERSION_AVTAB || p->policyvers > POLICYDB_VERSION_PERMISSIVE) {
		for (i = 0; i < p->p_types.nprim; i++) {
			if (p->type_val_to_struct[i]) {
				if (ebitmap_get_bit(&flavors[SYM_TYPES].gaps, i))
					goto bad;
				if (validate_type_datum(handle, p->type_val_to_struct[i], flavors))
					goto bad;
			} else {
				if (!ebitmap_get_bit(&flavors[SYM_TYPES].gaps, i))
					goto bad;
			}
		}
	}

	for (i = 0; i < p->p_users.nprim; i++) {
		if (p->user_val_to_struct[i]) {
			if (ebitmap_get_bit(&flavors[SYM_USERS].gaps, i))
				goto bad;
			if (validate_user_datum(handle, p->user_val_to_struct[i], flavors))
				goto bad;
		} else {
			if (!ebitmap_get_bit(&flavors[SYM_USERS].gaps, i))
				goto bad;
		}
	}

	return 0;

bad:
	ERR(handle, "Invalid datum arrays");
	return -1;
}

/*
 * Functions to validate a kernel policydb
 */

static int validate_avtab_key(avtab_key_t *key, validate_t flavors[])
{
	if (validate_value(key->source_type, &flavors[SYM_TYPES]))
		goto bad;
	if (validate_value(key->target_type, &flavors[SYM_TYPES]))
		goto bad;
	if (validate_value(key->target_class, &flavors[SYM_CLASSES]))
		goto bad;

	return 0;

bad:
	return -1;
}

static int validate_avtab_key_wrapper(avtab_key_t *k,  __attribute__ ((unused)) avtab_datum_t *d, void *args)
{
	validate_t *flavors = (validate_t *)args;
	return validate_avtab_key(k, flavors);
}

static int validate_avtab(sepol_handle_t *handle, avtab_t *avtab, validate_t flavors[])
{
	if (avtab_map(avtab, validate_avtab_key_wrapper, flavors)) {
		ERR(handle, "Invalid avtab");
		return -1;
	}

	return 0;
}

static int validate_cond_av_list(sepol_handle_t *handle, cond_av_list_t *cond_av, validate_t flavors[])
{
	avtab_ptr_t avtab_ptr;

	for (; cond_av; cond_av = cond_av->next) {
		for (avtab_ptr = cond_av->node; avtab_ptr; avtab_ptr = avtab_ptr->next) {
			if (validate_avtab_key(&avtab_ptr->key, flavors)) {
				ERR(handle, "Invalid cond av list");
				return -1;
			}
		}
	}

	return 0;
}

static int validate_avrules(sepol_handle_t *handle, avrule_t *avrule, validate_t flavors[])
{
	class_perm_node_t *class;

	for (; avrule; avrule = avrule->next) {
		if (validate_type_set(&avrule->stypes, &flavors[SYM_TYPES]))
			goto bad;
		if (validate_type_set(&avrule->ttypes, &flavors[SYM_TYPES]))
			goto bad;
		class = avrule->perms;
		for (; class; class = class->next) {
			if (validate_value(class->tclass, &flavors[SYM_CLASSES]))
				goto bad;
		}
	}

	return 0;

bad:
	ERR(handle, "Invalid avrule");
	return -1;
}

static int validate_bool_id_array(sepol_handle_t *handle, uint32_t bool_ids[], unsigned int nbools, validate_t *bool)
{
	unsigned int i;

	if (nbools >= COND_MAX_BOOLS)
		goto bad;

	for (i=0; i < nbools; i++) {
		if (validate_value(bool_ids[i], bool))
			goto bad;
	}

	return 0;

bad:
	ERR(handle, "Invalid bool id array");
	return -1;
}

static int validate_cond_list(sepol_handle_t *handle, cond_list_t *cond, validate_t flavors[])
{
	for (; cond; cond = cond->next) {
		if (validate_cond_av_list(handle, cond->true_list, flavors))
			goto bad;
		if (validate_cond_av_list(handle, cond->false_list, flavors))
			goto bad;
		if (validate_avrules(handle, cond->avtrue_list, flavors))
			goto bad;
		if (validate_avrules(handle, cond->avfalse_list, flavors))
			goto bad;
		if (validate_bool_id_array(handle, cond->bool_ids, cond->nbools, &flavors[SYM_BOOLS]))
			goto bad;
	}

	return 0;

bad:
	ERR(handle, "Invalid cond list");
	return -1;
}

static int validate_role_transes(sepol_handle_t *handle, role_trans_t *role_trans, validate_t flavors[])
{
	for (; role_trans; role_trans = role_trans->next) {
		if (validate_value(role_trans->role, &flavors[SYM_ROLES]))
			goto bad;
		if (validate_value(role_trans->type, &flavors[SYM_TYPES]))
			goto bad;
		if (validate_value(role_trans->tclass, &flavors[SYM_CLASSES]))
			goto bad;
		if (validate_value(role_trans->new_role, &flavors[SYM_ROLES]))
			goto bad;
	}

	return 0;

bad:
	ERR(handle, "Invalid role trans");
	return -1;
}

static int validate_role_allows(sepol_handle_t *handle, role_allow_t *role_allow, validate_t flavors[])
{
	for (; role_allow; role_allow = role_allow->next) {
		if (validate_value(role_allow->role, &flavors[SYM_ROLES]))
			goto bad;
		if (validate_value(role_allow->new_role, &flavors[SYM_ROLES]))
			goto bad;
	}

	return 0;

bad:
	ERR(handle, "Invalid role allow");
	return -1;
}

static int validate_filename_trans(hashtab_key_t k, hashtab_datum_t d, void *args)
{
	filename_trans_key_t *ftk = (filename_trans_key_t *)k;
	filename_trans_datum_t *ftd = d;
	validate_t *flavors = (validate_t *)args;

	if (validate_value(ftk->ttype, &flavors[SYM_TYPES]))
		goto bad;
	if (validate_value(ftk->tclass, &flavors[SYM_CLASSES]))
		goto bad;
	for (; ftd; ftd = ftd->next) {
		if (validate_ebitmap(&ftd->stypes, &flavors[SYM_TYPES]))
			goto bad;
		if (validate_value(ftd->otype, &flavors[SYM_TYPES]))
			goto bad;
	}

	return 0;

bad:
	return -1;
}

static int validate_filename_trans_hashtab(sepol_handle_t *handle, hashtab_t filename_trans, validate_t flavors[])
{
	if (hashtab_map(filename_trans, validate_filename_trans, flavors)) {
		ERR(handle, "Invalid filename trans");
		return -1;
	}

	return 0;
}

/*
 * Functions to validate a module policydb
 */

static int validate_role_trans_rules(sepol_handle_t *handle, role_trans_rule_t *role_trans, validate_t flavors[])
{
	for (; role_trans; role_trans = role_trans->next) {
		if (validate_role_set(&role_trans->roles, &flavors[SYM_ROLES]))
			goto bad;
		if (validate_type_set(&role_trans->types, &flavors[SYM_TYPES]))
			goto bad;
		if (validate_ebitmap(&role_trans->classes, &flavors[SYM_CLASSES]))
			goto bad;
		if (validate_value(role_trans->new_role, &flavors[SYM_ROLES]))
			goto bad;
	}

	return 0;

bad:
	ERR(handle, "Invalid role trans rule");
	return -1;
}

static int validate_role_allow_rules(sepol_handle_t *handle, role_allow_rule_t *role_allow, validate_t flavors[])
{
	for (; role_allow; role_allow = role_allow->next) {
		if (validate_role_set(&role_allow->roles, &flavors[SYM_ROLES]))
			goto bad;
		if (validate_role_set(&role_allow->new_roles, &flavors[SYM_ROLES]))
			goto bad;
	}

	return 0;

bad:
	ERR(handle, "Invalid role allow rule");
	return -1;
}

static int validate_range_trans_rules(sepol_handle_t *handle, range_trans_rule_t *range_trans, validate_t flavors[])
{
	for (; range_trans; range_trans = range_trans->next) {
		if (validate_type_set(&range_trans->stypes, &flavors[SYM_TYPES]))
			goto bad;
		if (validate_type_set(&range_trans->ttypes, &flavors[SYM_TYPES]))
			goto bad;
		if (validate_ebitmap(&range_trans->tclasses, &flavors[SYM_CLASSES]))
			goto bad;
		if (validate_mls_semantic_range(&range_trans->trange, &flavors[SYM_LEVELS], &flavors[SYM_CATS]))
			goto bad;
	}

	return 0;

bad:
	ERR(handle, "Invalid range trans rule");
	return -1;
}

static int validate_scope_index(sepol_handle_t *handle, scope_index_t *scope_index, validate_t flavors[])
{
	if (validate_ebitmap(&scope_index->p_classes_scope, &flavors[SYM_CLASSES]))
		goto bad;
	if (validate_ebitmap(&scope_index->p_roles_scope, &flavors[SYM_ROLES]))
		goto bad;
	if (validate_ebitmap(&scope_index->p_types_scope, &flavors[SYM_TYPES]))
		goto bad;
	if (validate_ebitmap(&scope_index->p_users_scope, &flavors[SYM_USERS]))
		goto bad;
	if (validate_ebitmap(&scope_index->p_bools_scope, &flavors[SYM_BOOLS]))
		goto bad;
	if (validate_ebitmap(&scope_index->p_sens_scope, &flavors[SYM_LEVELS]))
		goto bad;
	if (validate_ebitmap(&scope_index->p_cat_scope, &flavors[SYM_CATS]))
		goto bad;
	if (scope_index->class_perms_len > flavors[SYM_CLASSES].nprim)
		goto bad;

	return 0;

bad:
	ERR(handle, "Invalid scope");
	return -1;
}


static int validate_filename_trans_rules(sepol_handle_t *handle, filename_trans_rule_t *filename_trans, validate_t flavors[])
{
	for (; filename_trans; filename_trans = filename_trans->next) {
		if (validate_type_set(&filename_trans->stypes, &flavors[SYM_TYPES]))
			goto bad;
		if (validate_type_set(&filename_trans->ttypes, &flavors[SYM_TYPES]))
			goto bad;
		if (validate_value(filename_trans->tclass,&flavors[SYM_CLASSES] ))
			goto bad;
		if (validate_value(filename_trans->otype, &flavors[SYM_TYPES]))
			goto bad;
	}

	return 0;

bad:
	ERR(handle, "Invalid filename trans rule list");
	return -1;
}

static int validate_datum(__attribute__ ((unused))hashtab_key_t k, hashtab_datum_t d, void *args)
{
	symtab_datum_t *s = d;
	uint32_t *nprim = (uint32_t *)args;

	return !value_isvalid(s->value, *nprim);
}

static int validate_symtabs(sepol_handle_t *handle, symtab_t symtabs[], validate_t flavors[])
{
	unsigned int i;

	for (i = 0; i < SYM_NUM; i++) {
		if (hashtab_map(symtabs[i].table, validate_datum, &flavors[i].nprim)) {
			ERR(handle, "Invalid symtab");
			return -1;
		}
	}

	return 0;
}

static int validate_avrule_blocks(sepol_handle_t *handle, avrule_block_t *avrule_block, validate_t flavors[])
{
	avrule_decl_t *decl;

	for (; avrule_block; avrule_block = avrule_block->next) {
		for (decl = avrule_block->branch_list; decl != NULL; decl = decl->next) {
			if (validate_cond_list(handle, decl->cond_list, flavors))
				goto bad;
			if (validate_avrules(handle, decl->avrules, flavors))
				goto bad;
			if (validate_role_trans_rules(handle, decl->role_tr_rules, flavors))
				goto bad;
			if (validate_role_allow_rules(handle, decl->role_allow_rules, flavors))
				goto bad;
			if (validate_range_trans_rules(handle, decl->range_tr_rules, flavors))
				goto bad;
			if (validate_scope_index(handle, &decl->required, flavors))
				goto bad;
			if (validate_scope_index(handle, &decl->declared, flavors))
				goto bad;
			if (validate_filename_trans_rules(handle, decl->filename_trans_rules, flavors))
				goto bad;
			if (validate_symtabs(handle, decl->symtab, flavors))
				goto bad;
		}
	}

	return 0;

bad:
	ERR(handle, "Invalid avrule block");
	return -1;
}

static void validate_array_destroy(validate_t flavors[])
{
	unsigned int i;

	for (i = 0; i < SYM_NUM; i++) {
		ebitmap_destroy(&flavors[i].gaps);
	}
}

/*
 * Validate policydb
 */
int validate_policydb(sepol_handle_t *handle, policydb_t *p)
{
	validate_t flavors[SYM_NUM] = {};

	if (validate_array_init(p, flavors))
		goto bad;

	if (p->policy_type == POLICY_KERN) {
		if (validate_avtab(handle, &p->te_avtab, flavors))
			goto bad;
		if (p->policyvers >= POLICYDB_VERSION_BOOL)
			if (validate_cond_list(handle, p->cond_list, flavors))
				goto bad;
		if (validate_role_transes(handle, p->role_tr, flavors))
			goto bad;
		if (validate_role_allows(handle, p->role_allow, flavors))
			goto bad;
		if (p->policyvers >= POLICYDB_VERSION_FILENAME_TRANS)
			if (validate_filename_trans_hashtab(handle, p->filename_trans, flavors))
				goto bad;
	} else {
		if (validate_avrule_blocks(handle, p->global, flavors))
			goto bad;
	}

	if (validate_scopes(handle, p->scope, p->global))
		goto bad;

	if (validate_datum_arrays(handle, p, flavors))
		goto bad;

	validate_array_destroy(flavors);

	return 0;

bad:
	ERR(handle, "Invalid policydb");
	validate_array_destroy(flavors);
	return -1;
}
