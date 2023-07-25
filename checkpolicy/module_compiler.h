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

#ifndef MODULE_COMPILER_H
#define MODULE_COMPILER_H

#include <sepol/policydb/hashtab.h>

/* Called when checkpolicy begins to parse a policy -- either at the
 * very beginning for a kernel/base policy, or after the module header
 * for policy modules.  Initialize the memory structures within.
 * Return 0 on success, -1 on error. */
int define_policy(int pass, int module_header_given);

/* Declare a symbol declaration to the current avrule_decl.  Check
 * that insertion is allowed here and that the symbol does not already
 * exist.  Returns 0 on success, 1 if symbol was already there (caller
 * needs to free() the datum), -1 if declarations not allowed, -2 for
 * duplicate declarations, -3 for all else.
 */
int declare_symbol(uint32_t symbol_type,
		   hashtab_key_t key, hashtab_datum_t datum,
		   uint32_t * dest_value, uint32_t * datum_value);

role_datum_t *declare_role(unsigned char isattr);
type_datum_t *declare_type(unsigned char primary, unsigned char isattr);
user_datum_t *declare_user(void);

type_datum_t *get_local_type(char *id, uint32_t value, unsigned char isattr);
role_datum_t *get_local_role(char *id, uint32_t value, unsigned char isattr);

/* Add a symbol to the current avrule_block's require section.  Note
 * that a module may not both declare and require the same symbol.
 * Returns 0 on success, -1 on error. */
int require_symbol(uint32_t symbol_type,
		   hashtab_key_t key, hashtab_datum_t datum,
		   uint32_t * dest_value, uint32_t * datum_value);

/* Enable a permission for a class within the current avrule_decl.
 * Return 0 on success, -1 if out of memory. */
int add_perm_to_class(uint32_t perm_value, uint32_t class_value);

/* Functions called from REQUIRE blocks.  Add the first symbol on the
 * id_queue to this avrule_decl's scope if not already there.
 * c.f. require_symbol(). */
int require_class(int pass);
int require_role(int pass);
int require_type(int pass);
int require_attribute(int pass);
int require_attribute_role(int pass);
int require_user(int pass);
int require_bool(int pass);
int require_tunable(int pass);
int require_sens(int pass);
int require_cat(int pass);

/* Check if an identifier is within the scope of the current
 * declaration or any of its parents.  Return 1 if it is, 0 if not.
 * If the identifier is not known at all then return 1 (truth).  */
int is_id_in_scope(uint32_t symbol_type, const_hashtab_key_t id);

/* Check if a particular permission is within the scope of the current
 * declaration or any of its parents.  Return 1 if it is, 0 if not.
 * If the identifier is not known at all then return 1 (truth).  */
int is_perm_in_scope(const_hashtab_key_t perm_id, const_hashtab_key_t class_id);

/* Search the current avrules block for a conditional with the same
 * expression as 'cond'.  If the conditional does not exist then
 * create one.  Either way, return the conditional. */
cond_list_t *get_current_cond_list(cond_list_t * cond);

/* Append rule to the current avrule_block. */
void append_cond_list(cond_list_t * cond);
void append_avrule(avrule_t * avrule);
void append_role_trans(role_trans_rule_t * role_tr_rules);
void append_role_allow(role_allow_rule_t * role_allow_rules);
void append_range_trans(range_trans_rule_t * range_tr_rules);
void append_filename_trans(filename_trans_rule_t * filename_trans_rules);

/* Create a new optional block and add it to the global policy.
 * During the second pass resolve the block's requirements.  Return 0
 * on success, -1 on error.
 */
int begin_optional(int pass);
int end_optional(int pass);

/* ELSE blocks are similar to normal blocks with the following two
 * limitations:
 *   - no declarations are allowed within else branches
 *   - no REQUIRES are allowed; the else branch inherits the parent's
 *     requirements
 */
int begin_optional_else(int pass);

/* Called whenever existing an avrule block.  Check that the block had
 * a non-empty REQUIRE section.  If so pop the block off of the scop
 * stack and return 0.  If not then send an error to yyerror and
 * return -1. */
int end_avrule_block(int pass);

#endif
