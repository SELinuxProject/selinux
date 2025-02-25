/* Author : Joshua Brindle <jbrindle@tresys.com>
 *	    Karl MacMillan <kmacmillan@tresys.com>
 *          Jason Tang     <jtang@tresys.com>
 *	Added support for binary policy modules
 *
 * Copyright (C) 2004 - 2005 Tresys Technology, LLC
 *	This program is free software; you can redistribute it and/or modify
 *  	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, version 2.
 */

#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <sepol/policydb/policydb.h>
#include <sepol/policydb/avrule_block.h>
#include <sepol/policydb/conditional.h>

#include "queue.h"
#include "module_compiler.h"

typedef struct scope_stack {
	int type;		/* 1 = avrule block, 2 = conditional */
	avrule_decl_t *decl;	/* if in an avrule block, which
				 * declaration is current */
	avrule_t *last_avrule;
	int in_else;		/* if in an avrule block, within ELSE branch */
	int require_given;	/* 1 if this block had at least one require */
	struct scope_stack *parent;
} scope_stack_t;

extern policydb_t *policydbp;
extern queue_t id_queue;
extern int yyerror(const char *msg);
__attribute__ ((format(printf, 1, 2)))
extern void yyerror2(const char *fmt, ...);

static int push_stack(int stack_type, ...);
static void pop_stack(void);

/* keep track of the last item added to the stack */
static scope_stack_t *stack_top = NULL;
static avrule_block_t *last_block;
static uint32_t next_decl_id = 1;

static const char * const flavor_str[SYM_NUM] = {
	[SYM_COMMONS] = "common",
	[SYM_CLASSES] = "class",
	[SYM_ROLES] = "role",
	[SYM_TYPES] = "type",
	[SYM_USERS] = "user",
	[SYM_BOOLS] = "bool",
	[SYM_LEVELS] = "level",
	[SYM_CATS] = "cat"
};

static void print_error_msg(int ret, uint32_t symbol_type)
{
	switch (ret) {
	case -3:
		yyerror("Out of memory!");
		break;
	case -2:
		yyerror2("Duplicate declaration of %s", flavor_str[symbol_type]);
		break;
	case -1:
		yyerror2("Could not declare %s here", flavor_str[symbol_type]);
		break;
	default:
		yyerror2("Unknown error %d", ret);
	}
}

int define_policy(int pass, int module_header_given)
{
	char *id;

	if (module_header_given) {
		if (policydbp->policy_type != POLICY_MOD) {
			yyerror
			    ("Module specification found while not building a policy module.");
			return -1;
		}

		if (pass == 2) {
			while ((id = queue_remove(id_queue)) != NULL)
				free(id);
		} else {
			id = (char *)queue_remove(id_queue);
			if (!id) {
				yyerror("no module name");
				return -1;
			}
			free(policydbp->name);
			policydbp->name = id;
			if ((policydbp->version =
			     queue_remove(id_queue)) == NULL) {
				yyerror
				    ("Expected a module version but none was found.");
				return -1;
			}
		}
	} else {
		if (policydbp->policy_type == POLICY_MOD) {
			yyerror
			    ("Building a policy module, but no module specification found.");
			return -1;
		}
	}
	/* the first declaration within the global avrule
	   block will always have an id of 1 */
	next_decl_id = 2;

	/* reset the scoping stack */
	while (stack_top != NULL) {
		pop_stack();
	}
	if (push_stack(1, policydbp->global, policydbp->global->branch_list) ==
	    -1) {
		return -1;
	}
	last_block = policydbp->global;
	return 0;
}

/* Given the current parse stack, returns 1 if a declaration or require would
 * be allowed here or 0 if not.  For example, declarations and requirements are
 * not allowed in conditionals, so if there are any conditionals in the
 * current scope stack then this would return a 0.
 */
static int is_creation_allowed(void)
{
	if (stack_top->type != 1 || stack_top->in_else) {
		return 0;
	}
	return 1;
}

/* Attempt to declare or require a symbol within the current scope.
 * Returns:
 *  0: Success - Symbol had not been previously created.
 *  1: Success - Symbol had already been created and caller must free datum.
 * -1: Failure - Symbol cannot be created here
 * -2: Failure - Duplicate declaration or type/attribute mismatch
 * -3: Failure - Out of memory or some other error
 */
static int create_symbol(uint32_t symbol_type, hashtab_key_t key, hashtab_datum_t datum,
			 uint32_t * dest_value, uint32_t scope)
{
	avrule_decl_t *decl = stack_top->decl;
	int ret;

	if (!is_creation_allowed()) {
		return -1;
	}

	ret = symtab_insert(policydbp, symbol_type, key, datum, scope,
			    decl->decl_id, dest_value);

	if (ret == 1 && dest_value) {
		hashtab_datum_t s =
			hashtab_search(policydbp->symtab[symbol_type].table,
				       key);
		assert(s != NULL);

		if (symbol_type == SYM_LEVELS) {
			*dest_value = ((level_datum_t *)s)->level->sens;
		} else {
			*dest_value = ((symtab_datum_t *)s)->value;
		}
	} else if (ret == -2) {
		return -2;
	} else if (ret < 0) {
		return -3;
	}

	return ret;
}

/* Attempt to declare a symbol within the current declaration.  If
 * currently within a non-conditional and in a non-else branch then
 * insert the symbol, return 0 on success if symbol was undeclared.
 * For roles and users, it is legal to have multiple declarations; as
 * such return 1 to indicate that caller must free() the datum because
 * it was not added.  If symbols may not be declared here return -1.
 * For duplicate declarations return -2.  For all else, including out
 * of memory, return -3.  Note that dest_value and datum_value might
 * not be restricted pointers. */
int declare_symbol(uint32_t symbol_type,
		   hashtab_key_t key, hashtab_datum_t datum,
		   uint32_t * dest_value, const uint32_t * datum_value)
{
	avrule_decl_t *decl = stack_top->decl;
	int ret = create_symbol(symbol_type, key, datum, dest_value, SCOPE_DECL);

	if (ret < 0) {
		return ret;
	}

	if (ebitmap_set_bit(decl->declared.scope + symbol_type,
			    *datum_value - 1, 1)) {
		return -3;
	}

	return ret;
}

static int role_implicit_bounds(hashtab_t roles_tab,
				char *role_id, role_datum_t *role)
{
	role_datum_t *bounds;
	char *bounds_id, *delim;

	delim = strrchr(role_id, '.');
	if (!delim)
		return 0;	/* no implicit boundary */

	bounds_id = strdup(role_id);
	if (!bounds_id) {
		yyerror("out of memory");
		return -1;
	}
	bounds_id[(size_t)(delim - role_id)] = '\0';

	bounds = hashtab_search(roles_tab, bounds_id);
	if (!bounds) {
		yyerror2("role %s doesn't exist, is implicit bounds of %s",
			 bounds_id, role_id);
		free(bounds_id);
		return -1;
	}

	if (!role->bounds)
		role->bounds = bounds->s.value;
	else if (role->bounds != bounds->s.value) {
		yyerror2("role %s has inconsistent bounds %s/%s",
			 role_id, bounds_id,
			 policydbp->p_role_val_to_name[role->bounds - 1]);
		free(bounds_id);
		return -1;
	}
	free(bounds_id);

	return 0;
}

static int create_role(uint32_t scope, unsigned char isattr, role_datum_t **role, char **key)
{
	char *id = queue_remove(id_queue);
	role_datum_t *datum = NULL;
	int ret;
	uint32_t value;

	*role = NULL;
	*key = NULL;
	isattr = isattr ? ROLE_ATTRIB : ROLE_ROLE;

	if (id == NULL) {
		yyerror("no role name");
		return -1;
	}

	datum = malloc(sizeof(*datum));
	if (datum == NULL) {
		yyerror("Out of memory!");
		free(id);
		return -1;
	}

	role_datum_init(datum);
	datum->flavor = isattr;

	if (scope == SCOPE_DECL) {
		ret = declare_symbol(SYM_ROLES, id, datum, &value, &value);
	} else {
		ret = require_symbol(SYM_ROLES, id, datum, &value, &value);
	}

	if (ret == 0) {
		datum->s.value = value;
		*role = datum;
		*key = strdup(id);
		if (*key == NULL) {
			yyerror("Out of memory!");
			return -1;
		}
	} else if (ret == 1) {
		*role = hashtab_search(policydbp->symtab[SYM_ROLES].table, id);
		if (*role && (isattr != (*role)->flavor)) {
			yyerror2("Identifier %s used as both an attribute and a role",
				 id);
			*role = NULL;
			free(id);
			role_datum_destroy(datum);
			free(datum);
			return -1;
		}
		datum->s.value = value;
		*role = datum;
		*key = id;
	} else {
		print_error_msg(ret, SYM_ROLES);
		free(id);
		role_datum_destroy(datum);
		free(datum);
	}

	return ret;
}

role_datum_t *declare_role(unsigned char isattr)
{
	char *key = NULL;
	role_datum_t *role = NULL;
	role_datum_t *dest_role = NULL;
	hashtab_t roles_tab;
	int ret, ret2;

	ret = create_role(SCOPE_DECL, isattr, &role, &key);
	if (ret < 0) {
		return NULL;
	}

	/* create a new role_datum_t for this decl, if necessary */
	assert(stack_top->type == 1);

	if (stack_top->parent == NULL) {
		/* in parent, so use global symbol table */
		roles_tab = policydbp->p_roles.table;
	} else {
		roles_tab = stack_top->decl->p_roles.table;
	}

	dest_role = hashtab_search(roles_tab, key);
	if (dest_role == NULL) {
		if (ret == 0) {
			dest_role = malloc(sizeof(*dest_role));
			if (dest_role == NULL) {
				yyerror("Out of memory!");
				free(key);
				return NULL;
			}
			role_datum_init(dest_role);
			dest_role->s.value = role->s.value;
			dest_role->flavor = role->flavor;
		} else {
			dest_role = role;
		}
		ret2 = role_implicit_bounds(roles_tab, key, dest_role);
		if (ret2 != 0) {
			free(key);
			role_datum_destroy(dest_role);
			free(dest_role);
			return NULL;
		}
		ret2 = hashtab_insert(roles_tab, key, dest_role);
		if (ret2 != 0) {
			yyerror("Out of memory!");
			free(key);
			role_datum_destroy(dest_role);
			free(dest_role);
			return NULL;
		}
	} else {
		free(key);
		if (ret == 1) {
			role_datum_destroy(role);
			free(role);
		}
	}

	if (ret == 0) {
		ret2 = ebitmap_set_bit(&dest_role->dominates, dest_role->s.value - 1, 1);
		if (ret2 != 0) {
			yyerror("out of memory");
			return NULL;
		}
	}

	return dest_role;
}

static int create_type(uint32_t scope, unsigned char isattr, type_datum_t **type)
{
	char *id;
	type_datum_t *datum;
	int ret;
	uint32_t value = 0;

	*type = NULL;
	isattr = isattr ? TYPE_ATTRIB : TYPE_TYPE;

	id = (char *)queue_remove(id_queue);
	if (!id) {
		yyerror("no type/attribute name?");
		return -1;
	}
	if (strcmp(id, "self") == 0) {
		yyerror("\"self\" is a reserved type name.");
		free(id);
		return -1;
	}

	datum = malloc(sizeof(*datum));
	if (!datum) {
		yyerror("Out of memory!");
		free(id);
		return -1;
	}
	type_datum_init(datum);
	datum->primary = 1;
	datum->flavor = isattr;

	if (scope == SCOPE_DECL) {
		ret = declare_symbol(SYM_TYPES, id, datum, &value, &value);
	} else {
		ret = require_symbol(SYM_TYPES, id, datum, &value, &value);
	}

	if (ret == 0) {
		datum->s.value = value;
		*type = datum;
	} else if (ret == 1) {
		type_datum_destroy(datum);
		free(datum);
		*type = hashtab_search(policydbp->symtab[SYM_TYPES].table, id);
		if (*type && (isattr != (*type)->flavor)) {
			yyerror2("Identifier %s used as both an attribute and a type",
				 id);
			*type = NULL;
			free(id);
			return -1;
		}
		free(id);
	} else {
		print_error_msg(ret, SYM_TYPES);
		free(id);
		type_datum_destroy(datum);
		free(datum);
	}

	return ret;
}

type_datum_t *declare_type(unsigned char primary, unsigned char isattr)
{
	type_datum_t *type = NULL;
	int ret = create_type(SCOPE_DECL, isattr, &type);

	if (ret == 0) {
		type->primary = primary;
	}

	return type;
}

static int user_implicit_bounds(hashtab_t users_tab,
				char *user_id, user_datum_t *user)
{
	user_datum_t *bounds;
	char *bounds_id, *delim;

	delim = strrchr(user_id, '.');
	if (!delim)
		return 0;	/* no implicit boundary */

	bounds_id = strdup(user_id);
	if (!bounds_id) {
		yyerror("out of memory");
		return -1;
	}
	bounds_id[(size_t)(delim - user_id)] = '\0';

	bounds = hashtab_search(users_tab, bounds_id);
	if (!bounds) {
		yyerror2("user %s doesn't exist, is implicit bounds of %s",
			 bounds_id, user_id);
		free(bounds_id);
		return -1;
	}

	if (!user->bounds)
		user->bounds = bounds->s.value;
	else if (user->bounds != bounds->s.value) {
		yyerror2("user %s has inconsistent bounds %s/%s",
			 user_id, bounds_id,
			 policydbp->p_role_val_to_name[user->bounds - 1]);
		free(bounds_id);
		return -1;
	}
	free(bounds_id);

	return 0;
}

static int create_user(uint32_t scope, user_datum_t **user, char **key)
{
	char *id = queue_remove(id_queue);
	user_datum_t *datum = NULL;
	int ret;
	uint32_t value;

	*user = NULL;
	*key = NULL;

	if (id == NULL) {
		yyerror("no user name");
		return -1;
	}

	datum = malloc(sizeof(*datum));
	if (datum == NULL) {
		yyerror("Out of memory!");
		free(id);
		return -1;
	}

	user_datum_init(datum);

	if (scope == SCOPE_DECL) {
		ret = declare_symbol(SYM_USERS, id, datum, &value, &value);
	} else {
		ret = require_symbol(SYM_USERS, id, datum, &value, &value);
	}

	if (ret == 0) {
		datum->s.value = value;
		*user = datum;
		*key = strdup(id);
		if (*key == NULL) {
			yyerror("Out of memory!");
			return -1;
		}
	} else if (ret == 1) {
		datum->s.value = value;
		*user = datum;
		*key = id;
	} else {
		print_error_msg(ret, SYM_USERS);
		free(id);
		user_datum_destroy(datum);
		free(datum);
	}

	return ret;
}

user_datum_t *declare_user(void)
{
	char *key = NULL;
	user_datum_t *user = NULL;
	user_datum_t *dest_user = NULL;
	hashtab_t users_tab;
	int ret, ret2;

	ret = create_user(SCOPE_DECL, &user, &key);
	if (ret < 0) {
		return NULL;
	}

	/* create a new user_datum_t for this decl, if necessary */
	assert(stack_top->type == 1);

	if (stack_top->parent == NULL) {
		/* in parent, so use global symbol table */
		users_tab = policydbp->p_users.table;
	} else {
		users_tab = stack_top->decl->p_users.table;
	}

	dest_user = hashtab_search(users_tab, key);
	if (dest_user == NULL) {
		if (ret == 0) {
			dest_user = malloc(sizeof(*dest_user));
			if (dest_user == NULL) {
				yyerror("Out of memory!");
				free(key);
				return NULL;
			}
			user_datum_init(dest_user);
			dest_user->s.value = user->s.value;
		} else {
			dest_user = user;
		}
		ret2 = user_implicit_bounds(users_tab, key, dest_user);
		if (ret2 != 0) {
			free(key);
			user_datum_destroy(dest_user);
			free(dest_user);
			return NULL;
		}
		ret2 = hashtab_insert(users_tab, key, dest_user);
		if (ret2 != 0) {
			yyerror("Out of memory!");
			free(key);
			user_datum_destroy(dest_user);
			free(dest_user);
			return NULL;
		}
	} else {
		free(key);
		if (ret == 1) {
			user_datum_destroy(user);
			free(user);
		}
	}

	return dest_user;
}

/* Return a type_datum_t for the local avrule_decl with the given ID.
 * If it does not exist, create one with the same value as 'value'.
 * This function assumes that the ID is within scope.  c.f.,
 * is_id_in_scope().
 *
 * NOTE: this function usurps ownership of id afterwards.  The caller
 * shall not reference it nor free() it afterwards.
 */
type_datum_t *get_local_type(char *id, uint32_t value, unsigned char isattr)
{
	type_datum_t *dest_typdatum;
	hashtab_t types_tab;
	assert(stack_top->type == 1);
	if (stack_top->parent == NULL) {
		/* in global, so use global symbol table */
		types_tab = policydbp->p_types.table;
	} else {
		types_tab = stack_top->decl->p_types.table;
	}
	dest_typdatum = hashtab_search(types_tab, id);
	if (!dest_typdatum) {
		dest_typdatum = (type_datum_t *) malloc(sizeof(type_datum_t));
		if (dest_typdatum == NULL) {
			free(id);
			return NULL;
		}
		type_datum_init(dest_typdatum);
		dest_typdatum->s.value = value;
		dest_typdatum->flavor = isattr ? TYPE_ATTRIB : TYPE_TYPE;
		dest_typdatum->primary = 1;
		if (hashtab_insert(types_tab, id, dest_typdatum)) {
			free(id);
			type_datum_destroy(dest_typdatum);
			free(dest_typdatum);
			return NULL;
		}

	} else {
		free(id);
		if (dest_typdatum->flavor != isattr ? TYPE_ATTRIB : TYPE_TYPE) {
			return NULL;
		}
	}
	return dest_typdatum;
}

/* Return a role_datum_t for the local avrule_decl with the given ID.
 * If it does not exist, create one with the same value as 'value'.
 * This function assumes that the ID is within scope.  c.f.,
 * is_id_in_scope().
 *
 * NOTE: this function usurps ownership of id afterwards.  The caller
 * shall not reference it nor free() it afterwards.
 */
role_datum_t *get_local_role(char *id, uint32_t value, unsigned char isattr)
{
	role_datum_t *dest_roledatum;
	hashtab_t roles_tab;

	assert(stack_top->type == 1);

	if (stack_top->parent == NULL) {
		/* in global, so use global symbol table */
		roles_tab = policydbp->p_roles.table;
	} else {
		roles_tab = stack_top->decl->p_roles.table;
	}

	dest_roledatum = hashtab_search(roles_tab, id);
	if (!dest_roledatum) {
		dest_roledatum = (role_datum_t *)malloc(sizeof(role_datum_t));
		if (dest_roledatum == NULL) {
			free(id);
			return NULL;
		}

		role_datum_init(dest_roledatum);
		dest_roledatum->s.value = value;
		dest_roledatum->flavor = isattr ? ROLE_ATTRIB : ROLE_ROLE;

		if (hashtab_insert(roles_tab, id, dest_roledatum)) {
			free(id);
			role_datum_destroy(dest_roledatum);
			free(dest_roledatum);
			return NULL;
		}
	} else {
		free(id);
		if (dest_roledatum->flavor != isattr ? ROLE_ATTRIB : ROLE_ROLE)
			return NULL;
	}
	
	return dest_roledatum;
}

/* Attempt to require a symbol within the current scope.  If currently
 * within an optional (and not its else branch), add the symbol to the
 * required list.  Return 0 on success, 1 if caller needs to free()
 * datum.  If symbols may not be declared here return -1.  For duplicate
 * declarations return -2.  For all else, including out of memory,
 * return -3..  Note that dest_value and datum_value might not be
 * restricted pointers.
 */
int require_symbol(uint32_t symbol_type,
		   hashtab_key_t key, hashtab_datum_t datum,
		   uint32_t * dest_value, uint32_t * datum_value)
{
	avrule_decl_t *decl = stack_top->decl;
	int ret = create_symbol(symbol_type, key, datum, dest_value, SCOPE_REQ);

	if (ret < 0) {
		return ret;
	}

	if (ebitmap_set_bit(decl->required.scope + symbol_type,
			    *datum_value - 1, 1)) {
		return -3;
	}

	stack_top->require_given = 1;
	return ret;
}

int add_perm_to_class(uint32_t perm_value, uint32_t class_value)
{
	avrule_decl_t *decl = stack_top->decl;
	scope_index_t *scope;

	assert(perm_value >= 1);
	assert(class_value >= 1);
	scope = &decl->required;
	if (class_value > scope->class_perms_len) {
		uint32_t i;
		ebitmap_t *new_map = realloc(scope->class_perms_map,
					     class_value * sizeof(*new_map));
		if (new_map == NULL) {
			return -1;
		}
		scope->class_perms_map = new_map;
		for (i = scope->class_perms_len; i < class_value; i++) {
			ebitmap_init(scope->class_perms_map + i);
		}
		scope->class_perms_len = class_value;
	}
	if (ebitmap_set_bit(scope->class_perms_map + class_value - 1,
			    perm_value - 1, 1)) {
		return -1;
	}
	return 0;
}

static int perm_destroy(hashtab_key_t key, hashtab_datum_t datum, void *p
			__attribute__ ((unused)))
{
	if (key)
		free(key);
	free(datum);
	return 0;
}

static void class_datum_destroy(class_datum_t * cladatum)
{
	if (cladatum != NULL) {
		hashtab_map(cladatum->permissions.table, perm_destroy, NULL);
		hashtab_destroy(cladatum->permissions.table);
		free(cladatum);
	}
}

int require_class(int pass)
{
	char *class_id = queue_remove(id_queue);
	char *perm_id = NULL;
	class_datum_t *datum = NULL;
	perm_datum_t *perm = NULL;
	int ret;

	if (pass == 2) {
		free(class_id);
		while ((perm_id = queue_remove(id_queue)) != NULL)
			free(perm_id);
		return 0;
	}

	/* first add the class if it is not already there */
	if (class_id == NULL) {
		yyerror("no class name for class definition?");
		return -1;
	}

	if ((datum = calloc(1, sizeof(*datum))) == NULL ||
	    symtab_init(&datum->permissions, PERM_SYMTAB_SIZE)) {
		yyerror("Out of memory!");
		class_datum_destroy(datum);
		return -1;
	}
	ret =
	    require_symbol(SYM_CLASSES, class_id, datum, &datum->s.value,
			   &datum->s.value);
	if (ret < 0) {
		print_error_msg(ret, SYM_CLASSES);
		free(class_id);
		class_datum_destroy(datum);
		return -1;
	}

	if (ret == 0) {
		/* a new class was added; reindex everything */
		if (policydb_index_classes(policydbp)) {
			yyerror("Out of memory!");
			return -1;
		}
	} else {
		class_datum_destroy(datum);
		datum = hashtab_search(policydbp->p_classes.table, class_id);
		assert(datum);	/* the class datum should have existed */
		free(class_id);
	}

	/* now add each of the permissions to this class's requirements */
	while ((perm_id = queue_remove(id_queue)) != NULL) {
		int allocated = 0;

		/* Is the permission already in the table? */
		perm = hashtab_search(datum->permissions.table, perm_id);
		if (!perm && datum->comdatum)
			perm =
			    hashtab_search(datum->comdatum->permissions.table,
					   perm_id);
		if (perm) {
			/* Yes, drop the name. */
			free(perm_id);
		} else {
			/* No - allocate and insert an entry for it. */
			if (policydbp->policy_type == POLICY_BASE) {
				yyerror2
				    ("Base policy - require of permission %s without prior declaration.",
				     perm_id);
				free(perm_id);
				return -1;
			}
			if (datum->permissions.nprim >= PERM_SYMTAB_SIZE) {
				yyerror2("Class %s would have too many permissions "
					 "to fit in an access vector with permission %s",
					 policydbp->p_class_val_to_name[datum->s.value - 1],
					 perm_id);
				free(perm_id);
				return -1;
			}
			allocated = 1;
			if ((perm = malloc(sizeof(*perm))) == NULL) {
				yyerror("Out of memory!");
				free(perm_id);
				return -1;
			}
			memset(perm, 0, sizeof(*perm));
			ret =
			    hashtab_insert(datum->permissions.table, perm_id,
					   perm);
			if (ret) {
				yyerror("Out of memory!");
				free(perm_id);
				free(perm);
				return -1;
			}
			perm->s.value = datum->permissions.nprim + 1;
		}

		if (add_perm_to_class(perm->s.value, datum->s.value) == -1) {
			yyerror("Out of memory!");
			return -1;
		}

		/* Update number of primitives if we allocated one. */
		if (allocated)
			datum->permissions.nprim++;
	}
	return 0;
}

static int require_role_or_attribute(int pass, unsigned char isattr)
{
	char *key = NULL;
	role_datum_t *role = NULL;
	int ret;

	if (pass == 2) {
		free(queue_remove(id_queue));
		return 0;
	}

	ret = create_role(SCOPE_REQ, isattr, &role, &key);
	if (ret < 0) {
		return -1;
	}

	free(key);

	if (ret == 0) {
		ret = ebitmap_set_bit(&role->dominates, role->s.value - 1, 1);
		if (ret != 0) {
			yyerror("Out of memory");
			return -1;
		}
	} else {
		role_datum_destroy(role);
		free(role);
	}

	return 0;
}

int require_role(int pass)
{
	return require_role_or_attribute(pass, 0);
}

int require_attribute_role(int pass)
{
	return require_role_or_attribute(pass, 1);
}

static int require_type_or_attribute(int pass, unsigned char isattr)
{
	type_datum_t *type = NULL;
	int ret;

	if (pass == 2) {
		free(queue_remove(id_queue));
		return 0;
	}

	ret = create_type(SCOPE_REQ, isattr, &type);

	if (ret < 0) {
		return -1;
	}

	return 0;
}

int require_type(int pass)
{
	return require_type_or_attribute(pass, 0);
}

int require_attribute(int pass)
{
	return require_type_or_attribute(pass, 1);
}

int require_user(int pass)
{
	char *key = NULL;
	user_datum_t *user = NULL;
	int ret;

	if (pass == 1) {
		free(queue_remove(id_queue));
		return 0;
	}

	ret = create_user(SCOPE_REQ, &user, &key);
	if (ret < 0) {
		return -1;
	}

	free(key);

	if (ret == 1) {
		user_datum_destroy(user);
		free(user);
	}

	return 0;
}

static int require_bool_tunable(int pass, int is_tunable)
{
	char *id = queue_remove(id_queue);
	cond_bool_datum_t *booldatum = NULL;
	int retval;
	if (pass == 2) {
		free(id);
		return 0;
	}
	if (id == NULL) {
		yyerror("no boolean name");
		return -1;
	}
	if ((booldatum = calloc(1, sizeof(*booldatum))) == NULL) {
		cond_destroy_bool(id, booldatum, NULL);
		yyerror("Out of memory!");
		return -1;
	}
	if (is_tunable)
		booldatum->flags |= COND_BOOL_FLAGS_TUNABLE;
	retval =
	    require_symbol(SYM_BOOLS, id, booldatum,
			   &booldatum->s.value, &booldatum->s.value);
	if (retval != 0) {
		cond_destroy_bool(id, booldatum, NULL);
		if (retval < 0) {
			print_error_msg(retval, SYM_BOOLS);
			return -1;
		}
	}

	return 0;
}

int require_bool(int pass)
{
	return require_bool_tunable(pass, 0);
}

int require_tunable(int pass)
{
	return require_bool_tunable(pass, 1);
}

int require_sens(int pass)
{
	char *id = queue_remove(id_queue);
	level_datum_t *level = NULL;
	int retval;
	if (pass == 2) {
		free(id);
		return 0;
	}
	if (!id) {
		yyerror("no sensitivity name");
		return -1;
	}
	level = malloc(sizeof(level_datum_t));
	if (!level) {
		free(id);
		yyerror("Out of memory!");
		return -1;
	}
	level_datum_init(level);
	level->level = malloc(sizeof(mls_level_t));
	if (!level->level) {
		free(id);
		level_datum_destroy(level);
		free(level);
		yyerror("Out of memory!");
		return -1;
	}
	mls_level_init(level->level);
	retval = require_symbol(SYM_LEVELS, id, level,
				&level->level->sens, &level->level->sens);
	if (retval != 0) {
		free(id);
		mls_level_destroy(level->level);
		free(level->level);
		level_datum_destroy(level);
		free(level);
		if (retval < 0) {
			print_error_msg(retval, SYM_LEVELS);
			return -1;
		}
	}

	return 0;
}

int require_cat(int pass)
{
	char *id = queue_remove(id_queue);
	cat_datum_t *cat = NULL;
	int retval;
	if (pass == 2) {
		free(id);
		return 0;
	}
	if (!id) {
		yyerror("no category name");
		return -1;
	}
	cat = malloc(sizeof(cat_datum_t));
	if (!cat) {
		free(id);
		yyerror("Out of memory!");
		return -1;
	}
	cat_datum_init(cat);

	retval = require_symbol(SYM_CATS, id, cat,
				&cat->s.value, &cat->s.value);
	if (retval != 0) {
		free(id);
		cat_datum_destroy(cat);
		free(cat);
		if (retval < 0) {
			print_error_msg(retval, SYM_CATS);
			return -1;
		}
	}

	return 0;
}

static int is_scope_in_stack(const scope_datum_t * scope, const scope_stack_t * stack)
{
	uint32_t i;
	if (stack == NULL) {
		return 0;	/* no matching scope found */
	}
	if (stack->type == 1) {
		const avrule_decl_t *decl = stack->decl;
		for (i = 0; i < scope->decl_ids_len; i++) {
			if (scope->decl_ids[i] == decl->decl_id) {
				return 1;
			}
		}
	} else {
		/* note that conditionals can't declare or require
		 * symbols, so skip this level */
	}

	/* not within scope of this stack, so try its parent */
	return is_scope_in_stack(scope, stack->parent);
}

int is_id_in_scope(uint32_t symbol_type, const_hashtab_key_t id)
{
	const scope_datum_t *scope =
	    (scope_datum_t *) hashtab_search(policydbp->scope[symbol_type].
					     table, id);
	if (scope == NULL) {
		return 1;	/* id is not known, so return success */
	}
	return is_scope_in_stack(scope, stack_top);
}

static int is_perm_in_scope_index(uint32_t perm_value, uint32_t class_value,
				  const scope_index_t * scope)
{
	if (class_value > scope->class_perms_len) {
		return 1;
	}
	if (ebitmap_get_bit(scope->class_perms_map + class_value - 1,
			    perm_value - 1)) {
		return 1;
	}
	return 0;
}

static int is_perm_in_stack(uint32_t perm_value, uint32_t class_value,
			    const scope_stack_t * stack)
{
	if (stack == NULL) {
		return 0;	/* no matching scope found */
	}
	if (stack->type == 1) {
		avrule_decl_t *decl = stack->decl;
		if (is_perm_in_scope_index
		    (perm_value, class_value, &decl->required)
		    || is_perm_in_scope_index(perm_value, class_value,
					      &decl->declared)) {
			return 1;
		}
	} else {
		/* note that conditionals can't declare or require
		 * symbols, so skip this level */
	}

	/* not within scope of this stack, so try its parent */
	return is_perm_in_stack(perm_value, class_value, stack->parent);
}

int is_perm_in_scope(const_hashtab_key_t perm_id, const_hashtab_key_t class_id)
{
	const class_datum_t *cladatum =
	    (class_datum_t *) hashtab_search(policydbp->p_classes.table,
					     class_id);
	const perm_datum_t *perdatum;
	if (cladatum == NULL) {
		return 1;
	}
	perdatum = (perm_datum_t *) hashtab_search(cladatum->permissions.table,
						   perm_id);
	if (perdatum == NULL) {
		return 1;
	}
	return is_perm_in_stack(perdatum->s.value, cladatum->s.value,
				stack_top);
}

cond_list_t *get_current_cond_list(cond_list_t * cond)
{
	/* FIX ME: do something different here if in a nested
	 * conditional? */
	avrule_decl_t *decl = stack_top->decl;
	return get_decl_cond_list(policydbp, decl, cond);
}

/* Append the new conditional node to the existing ones.  During
 * expansion the list will be reversed -- i.e., the last AV rule will
 * be the first one listed in the policy.  This matches the behavior
 * of the upstream compiler. */
void append_cond_list(cond_list_t * cond)
{
	cond_list_t *old_cond = get_current_cond_list(cond);
	avrule_t *tmp;
	assert(old_cond != NULL);	/* probably out of memory */
	if (old_cond->avtrue_list == NULL) {
		old_cond->avtrue_list = cond->avtrue_list;
	} else {
		for (tmp = old_cond->avtrue_list; tmp->next != NULL;
		     tmp = tmp->next) ;
		tmp->next = cond->avtrue_list;
	}
	if (old_cond->avfalse_list == NULL) {
		old_cond->avfalse_list = cond->avfalse_list;
	} else {
		for (tmp = old_cond->avfalse_list; tmp->next != NULL;
		     tmp = tmp->next) ;
		tmp->next = cond->avfalse_list;
	}

	old_cond->flags |= cond->flags;
}

void append_avrule(avrule_t * avrule)
{
	avrule_decl_t *decl = stack_top->decl;

	/* currently avrules follow a completely different code path
	 * for handling avrules and compute types
	 * (define_cond_avrule_te_avtab, define_cond_compute_type);
	 * therefore there ought never be a conditional on top of the
	 * scope stack */
	assert(stack_top->type == 1);

	if (stack_top->last_avrule == NULL) {
		decl->avrules = avrule;
	} else {
		stack_top->last_avrule->next = avrule;
	}
	stack_top->last_avrule = avrule;
}

/* this doesn't actually append, but really prepends it */
void append_role_trans(role_trans_rule_t * role_tr_rules)
{
	avrule_decl_t *decl = stack_top->decl;

	/* role transitions are not allowed within conditionals */
	assert(stack_top->type == 1);

	role_tr_rules->next = decl->role_tr_rules;
	decl->role_tr_rules = role_tr_rules;
}

/* this doesn't actually append, but really prepends it */
void append_role_allow(role_allow_rule_t * role_allow_rules)
{
	avrule_decl_t *decl = stack_top->decl;

	/* role allows are not allowed within conditionals */
	assert(stack_top->type == 1);

	role_allow_rules->next = decl->role_allow_rules;
	decl->role_allow_rules = role_allow_rules;
}

/* this doesn't actually append, but really prepends it */
void append_filename_trans(filename_trans_rule_t * filename_trans_rules)
{
	avrule_decl_t *decl = stack_top->decl;

	/* filename transitions are not allowed within conditionals */
	assert(stack_top->type == 1);

	filename_trans_rules->next = decl->filename_trans_rules;
	decl->filename_trans_rules = filename_trans_rules;
}

/* this doesn't actually append, but really prepends it */
void append_range_trans(range_trans_rule_t * range_tr_rules)
{
	avrule_decl_t *decl = stack_top->decl;

	/* range transitions are not allowed within conditionals */
	assert(stack_top->type == 1);

	range_tr_rules->next = decl->range_tr_rules;
	decl->range_tr_rules = range_tr_rules;
}

int begin_optional(int pass)
{
	avrule_block_t *block = NULL;
	avrule_decl_t *decl;
	if (pass == 1) {
		/* allocate a new avrule block for this optional block */
		if ((block = avrule_block_create()) == NULL ||
		    (decl = avrule_decl_create(next_decl_id)) == NULL) {
			goto cleanup;
		}
		block->flags |= AVRULE_OPTIONAL;
		block->branch_list = decl;
		last_block->next = block;
	} else {
		/* select the next block from the chain built during pass 1 */
		block = last_block->next;
		assert(block != NULL &&
		       block->branch_list != NULL &&
		       block->branch_list->decl_id == next_decl_id);
		decl = block->branch_list;
	}
	if (push_stack(1, block, decl) == -1) {
		goto cleanup;
	}
	stack_top->last_avrule = NULL;
	last_block = block;
	next_decl_id++;
	return 0;
      cleanup:
	yyerror("Out of memory!");
	avrule_block_destroy(block);
	return -1;
}

int end_optional(int pass __attribute__ ((unused)))
{
	/* once nested conditionals are allowed, do the stack unfolding here */
	pop_stack();
	return 0;
}

int begin_optional_else(int pass)
{
	avrule_decl_t *decl;
	assert(stack_top->type == 1 && stack_top->in_else == 0);
	if (pass == 1) {
		/* allocate a new declaration and add it to the
		 * current chain */
		if ((decl = avrule_decl_create(next_decl_id)) == NULL) {
			yyerror("Out of memory!");
			return -1;
		}
		stack_top->decl->next = decl;
	} else {
		/* pick the (hopefully last) declaration of this
		   avrule block, built from pass 1 */
		decl = stack_top->decl->next;
		assert(decl != NULL &&
		       decl->next == NULL && decl->decl_id == next_decl_id);
	}
	stack_top->in_else = 1;
	stack_top->decl = decl;
	stack_top->last_avrule = NULL;
	stack_top->require_given = 0;
	next_decl_id++;
	return 0;
}

static int copy_requirements(avrule_decl_t * dest, const scope_stack_t * stack)
{
	uint32_t i;
	if (stack == NULL) {
		return 0;
	}
	if (stack->type == 1) {
		const scope_index_t *src_scope = &stack->decl->required;
		scope_index_t *dest_scope = &dest->required;
		for (i = 0; i < SYM_NUM; i++) {
			const ebitmap_t *src_bitmap = &src_scope->scope[i];
			ebitmap_t *dest_bitmap = &dest_scope->scope[i];
			if (ebitmap_union(dest_bitmap, src_bitmap)) {
				yyerror("Out of memory!");
				return -1;
			}
		}
		/* now copy class permissions */
		if (src_scope->class_perms_len > dest_scope->class_perms_len) {
			ebitmap_t *new_map =
			    realloc(dest_scope->class_perms_map,
				    src_scope->class_perms_len *
				    sizeof(*new_map));
			if (new_map == NULL) {
				yyerror("Out of memory!");
				return -1;
			}
			dest_scope->class_perms_map = new_map;
			for (i = dest_scope->class_perms_len;
			     i < src_scope->class_perms_len; i++) {
				ebitmap_init(dest_scope->class_perms_map + i);
			}
			dest_scope->class_perms_len =
			    src_scope->class_perms_len;
		}
		for (i = 0; i < src_scope->class_perms_len; i++) {
			const ebitmap_t *src_bitmap = &src_scope->class_perms_map[i];
			ebitmap_t *dest_bitmap =
			    &dest_scope->class_perms_map[i];
			if (ebitmap_union(dest_bitmap, src_bitmap)) {
				yyerror("Out of memory!");
				return -1;
			}
		}
	}
	return copy_requirements(dest, stack->parent);
}

/* During pass 1, check that at least one thing was required within
 * this block, for those places where a REQUIRED is necessary.  During
 * pass 2, have this block inherit its parents' requirements.  Return
 * 0 on success, -1 on failure. */
int end_avrule_block(int pass)
{
	avrule_decl_t *decl = stack_top->decl;
	assert(stack_top->type == 1);
	if (pass == 2) {
		/* this avrule_decl inherits all of its parents'
		 * requirements */
		if (copy_requirements(decl, stack_top->parent) == -1) {
			return -1;
		}
		return 0;
	}
	if (!stack_top->in_else && !stack_top->require_given) {
		if (policydbp->policy_type == POLICY_BASE
		    && stack_top->parent != NULL) {
			/* if this is base no require should be in the global block */
			return 0;
		} else {
			/* non-ELSE branches must have at least one thing required */
			yyerror("This block has no require section.");
			return -1;
		}
	}
	return 0;
}

/* Push a new scope on to the stack and update the 'last' pointer.
 * Return 0 on success, -1 if out * of memory. */
static int push_stack(int stack_type, ...)
{
	scope_stack_t *s = calloc(1, sizeof(*s));
	va_list ap;
	if (s == NULL) {
		return -1;
	}
	va_start(ap, stack_type);
	switch (s->type = stack_type) {
	case 1:{
			va_arg(ap, avrule_block_t *);
			s->decl = va_arg(ap, avrule_decl_t *);
			break;
		}
	case 2:{
			va_arg(ap, cond_list_t *);
			break;
		}
	default:
		/* invalid stack type given */
		assert(0);
	}
	va_end(ap);
	s->parent = stack_top;
	stack_top = s;
	return 0;
}

/* Pop off the most recently added from the stack.  Update the 'last'
 * pointer. */
static void pop_stack(void)
{
	scope_stack_t *parent;
	assert(stack_top != NULL);
	parent = stack_top->parent;
	free(stack_top);
	stack_top = parent;
}

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
void module_compiler_reset(void)
{
	while (stack_top)
		pop_stack();

	last_block = NULL;
	next_decl_id = 1;
}
#endif
