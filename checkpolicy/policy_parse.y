
/*
 * Author : Stephen Smalley, <stephen.smalley.work@gmail.com>
 */

/*
 * Updated: Trusted Computer Solutions, Inc. <dgoeddel@trustedcs.com>
 *
 *	Support for enhanced MLS infrastructure.
 *
 * Updated: David Caplan, <dac@tresys.com>
 *
 * 	Added conditional policy language extensions
 *
 * Updated: Joshua Brindle <jbrindle@tresys.com>
 *	    Karl MacMillan <kmacmillan@mentalrootkit.com>
 *          Jason Tang     <jtang@tresys.com>
 *
 *	Added support for binary policy modules
 *
 * Copyright (C) 2004-2005 Trusted Computer Solutions, Inc.
 * Copyright (C) 2003 - 2008 Tresys Technology, LLC
 * Copyright (C) 2007 Red Hat Inc.
 * Copyright (C) 2017 Mellanox Technologies Inc.
 *	This program is free software; you can redistribute it and/or modify
 *  	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, version 2.
 */

/* FLASK */

%{
#include <sys/types.h>
#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>

#include <sepol/policydb/expand.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/services.h>
#include <sepol/policydb/conditional.h>
#include <sepol/policydb/hierarchy.h>
#include <sepol/policydb/polcaps.h>
#include "queue.h"
#include "module_compiler.h"
#include "policy_define.h"

extern policydb_t *policydbp;
extern unsigned int pass;

extern char yytext[];
extern int yylex(void);
extern int yywarn(const char *msg);
extern int yyerror(const char *msg);

typedef int (* require_func_t)(int pass);

%}

%union {
	unsigned int val;
	uint64_t val64;
	uintptr_t valptr;
	void *ptr;
        require_func_t require_func;
}

%type <ptr> cond_expr cond_expr_prim cond_pol_list cond_else
%type <ptr> cond_allow_def cond_auditallow_def cond_auditdeny_def cond_dontaudit_def
%type <ptr> cond_xperm_allow_def cond_xperm_auditallow_def cond_xperm_dontaudit_def
%type <ptr> cond_transition_def cond_te_avtab_def cond_rule_def
%type <valptr> cexpr cexpr_prim op role_mls_op
%type <val> ipv4_addr_def number
%type <val64> number64
%type <require_func> require_decl_def

%token PATH
%token QPATH
%token FILENAME
%token COMMON
%token CLASS
%token CONSTRAIN
%token VALIDATETRANS
%token INHERITS
%token SID
%token ROLE
%token ROLEATTRIBUTE
%token ATTRIBUTE_ROLE
%token ROLES
%token TYPEALIAS
%token TYPEATTRIBUTE
%token TYPEBOUNDS
%token TYPE
%token TYPES
%token ALIAS
%token ATTRIBUTE
%token EXPANDATTRIBUTE
%token BOOL
%token TUNABLE
%token IF
%token ELSE
%token TYPE_TRANSITION
%token TYPE_MEMBER
%token TYPE_CHANGE
%token ROLE_TRANSITION
%token RANGE_TRANSITION
%token SENSITIVITY
%token DOMINANCE
%token DOM DOMBY INCOMP
%token CATEGORY
%token LEVEL
%token RANGE
%token MLSCONSTRAIN
%token MLSVALIDATETRANS
%token USER
%token NEVERALLOW
%token ALLOW
%token AUDITALLOW
%token AUDITDENY
%token DONTAUDIT
%token ALLOWXPERM
%token AUDITALLOWXPERM
%token DONTAUDITXPERM
%token NEVERALLOWXPERM
%token SOURCE
%token TARGET
%token SAMEUSER
%token FSCON PORTCON NETIFCON NODECON 
%token IBPKEYCON
%token IBENDPORTCON
%token PIRQCON IOMEMCON IOPORTCON PCIDEVICECON DEVICETREECON
%token FSUSEXATTR FSUSETASK FSUSETRANS
%token GENFSCON
%token U1 U2 U3 R1 R2 R3 T1 T2 T3 L1 L2 H1 H2
%token NOT AND OR XOR
%token CTRUE CFALSE
%token IDENTIFIER
%token NUMBER
%token EQUALS
%token NOTEQUAL
%token IPV4_ADDR
%token IPV4_CIDR
%token IPV6_ADDR
%token IPV6_CIDR
%token MODULE VERSION_IDENTIFIER REQUIRE OPTIONAL
%token POLICYCAP
%token PERMISSIVE
%token NEVERAUDIT
%token FILESYSTEM
%token DEFAULT_USER DEFAULT_ROLE DEFAULT_TYPE DEFAULT_RANGE
%token LOW_HIGH LOW HIGH GLBLUB
%token INVALID_CHAR

%left OR
%left XOR
%left AND
%right NOT
%left EQUALS NOTEQUAL
%%
policy			: base_policy
                        | module_policy
                        ;
base_policy             : { if (define_policy(pass, 0) == -1) YYABORT; }
                          classes initial_sids access_vectors
                          { if (pass == 1) { if (policydb_index_classes(policydbp)) YYABORT; }
                            else if (pass == 2) { if (policydb_index_others(NULL, policydbp, 0)) YYABORT; }}
			  opt_default_rules opt_mls te_rbac users opt_constraints 
                         { if (pass == 1) { if (policydb_index_bools(policydbp)) YYABORT; }
			   else if (pass == 2) { if (policydb_index_others(NULL, policydbp, 0)) YYABORT; }}
			  initial_sid_contexts opt_fs_contexts opt_fs_uses opt_genfs_contexts net_contexts opt_dev_contexts opt_ibpkey_contexts opt_ibendport_contexts
			;
classes			: class_def 
			| classes class_def
			;
class_def		: CLASS identifier
			{if (define_class()) YYABORT;}
			;
initial_sids 		: initial_sid_def 
			| initial_sids initial_sid_def
			;
initial_sid_def		: SID identifier
                        {if (define_initial_sid()) YYABORT;}
			;
access_vectors		: opt_common_perms av_perms
			;
opt_common_perms        : common_perms
                        |
                        ;
common_perms		: common_perms_def
			| common_perms common_perms_def
			;
common_perms_def	: COMMON identifier '{' identifier_list '}'
			{if (define_common_perms()) YYABORT;}
			;
av_perms		: av_perms_def
			| av_perms av_perms_def
			;
av_perms_def		: CLASS identifier '{' identifier_list '}'
			{if (define_av_perms(FALSE)) YYABORT;}
                        | CLASS identifier INHERITS identifier 
			{if (define_av_perms(TRUE)) YYABORT;}
                        | CLASS identifier INHERITS identifier '{' identifier_list '}'
			{if (define_av_perms(TRUE)) YYABORT;}
			;
opt_default_rules	: default_rules
			|
			;
default_rules		: default_user_def
			| default_role_def
			| default_type_def
			| default_range_def
			| default_rules default_user_def
			| default_rules default_role_def
			| default_rules default_type_def
			| default_rules default_range_def
			;
default_user_def	: DEFAULT_USER names SOURCE ';'
			{if (define_default_user(DEFAULT_SOURCE)) YYABORT; }
			| DEFAULT_USER names TARGET ';'
			{if (define_default_user(DEFAULT_TARGET)) YYABORT; }
			;
default_role_def	: DEFAULT_ROLE names SOURCE ';'
			{if (define_default_role(DEFAULT_SOURCE)) YYABORT; }
			| DEFAULT_ROLE names TARGET ';'
			{if (define_default_role(DEFAULT_TARGET)) YYABORT; }
			;
default_type_def	: DEFAULT_TYPE names SOURCE ';'
			{if (define_default_type(DEFAULT_SOURCE)) YYABORT;; }
			| DEFAULT_TYPE names TARGET ';'
			{if (define_default_type(DEFAULT_TARGET)) YYABORT; }
			;
default_range_def	: DEFAULT_RANGE names SOURCE LOW ';'
			{if (define_default_range(DEFAULT_SOURCE_LOW)) YYABORT; }
			| DEFAULT_RANGE names SOURCE HIGH ';'
			{if (define_default_range(DEFAULT_SOURCE_HIGH)) YYABORT; }
			| DEFAULT_RANGE names SOURCE LOW_HIGH ';'
			{if (define_default_range(DEFAULT_SOURCE_LOW_HIGH)) YYABORT; }
			| DEFAULT_RANGE names TARGET LOW ';'
			{if (define_default_range(DEFAULT_TARGET_LOW)) YYABORT; }
			| DEFAULT_RANGE names TARGET HIGH ';'
			{if (define_default_range(DEFAULT_TARGET_HIGH)) YYABORT; }
			| DEFAULT_RANGE names TARGET LOW_HIGH ';'
			{if (define_default_range(DEFAULT_TARGET_LOW_HIGH)) YYABORT; }
			| DEFAULT_RANGE names GLBLUB';'
			{if (define_default_range(DEFAULT_GLBLUB)) YYABORT; }
			;
opt_mls			: mls
                        | 
			;
mls			: sensitivities dominance opt_categories levels mlspolicy
			;
sensitivities	 	: sensitivity_def 
			| sensitivities sensitivity_def
			;
sensitivity_def		: SENSITIVITY identifier alias_def ';'
			{if (define_sens()) YYABORT;}
			| SENSITIVITY identifier ';'
			{if (define_sens()) YYABORT;}
	                ;
alias_def		: ALIAS names
			;
dominance		: DOMINANCE identifier 
			{if (define_dominance()) YYABORT;}
                        | DOMINANCE '{' identifier_list '}' 
			{if (define_dominance()) YYABORT;}
			;
opt_categories          : categories
                        |
                        ;
categories 		: category_def 
			| categories category_def
			;
category_def		: CATEGORY identifier alias_def ';'
			{if (define_category()) YYABORT;}
			| CATEGORY identifier ';'
			{if (define_category()) YYABORT;}
			;
levels	 		: level_def 
			| levels level_def
			;
level_def		: LEVEL identifier ':' id_comma_list ';'
			{if (define_level()) YYABORT;}
			| LEVEL identifier ';' 
			{if (define_level()) YYABORT;}
			;
mlspolicy		: mlspolicy_decl
			| mlspolicy mlspolicy_decl
			;
mlspolicy_decl		: mlsconstraint_def
			| mlsvalidatetrans_def
			;
mlsconstraint_def	: MLSCONSTRAIN names names cexpr ';'
			{ if (define_constraint((constraint_expr_t*)$4)) YYABORT; }
			;
mlsvalidatetrans_def	: MLSVALIDATETRANS names cexpr ';'
			{ if (define_validatetrans((constraint_expr_t*)$3)) YYABORT; }
			;
te_rbac			: te_rbac_decl
			| te_rbac te_rbac_decl
			;
te_rbac_decl		: te_decl
			| rbac_decl
                        | cond_stmt_def
			| optional_block
			| policycap_def
			| ';'
                        ;
rbac_decl		: attribute_role_def
			| role_type_def
                        | role_trans_def
 			| role_allow_def
			| roleattribute_def
			| role_attr_def
			;
te_decl			: attribute_def
                        | expandattribute_def
                        | type_def
                        | typealias_def
                        | typeattribute_def
                        | typebounds_def
                        | bool_def
			| tunable_def
                        | transition_def
                        | range_trans_def
                        | te_avtab_def
			| permissive_def
			| neveraudit_def
			;
attribute_def           : ATTRIBUTE identifier ';'
                        { if (define_attrib()) YYABORT;}
                        ;
expandattribute_def     : EXPANDATTRIBUTE names bool_val ';'
                        { if (expand_attrib()) YYABORT;}
                        ;
type_def		: TYPE identifier alias_def opt_attr_list ';'
                        {if (define_type(1)) YYABORT;}
	                | TYPE identifier opt_attr_list ';'
                        {if (define_type(0)) YYABORT;}
    			;
typealias_def           : TYPEALIAS identifier alias_def ';'
			{if (define_typealias()) YYABORT;}
			;
typeattribute_def	: TYPEATTRIBUTE identifier id_comma_list ';'
			{if (define_typeattribute()) YYABORT;}
			;
typebounds_def          : TYPEBOUNDS identifier id_comma_list ';'
                        {if (define_typebounds()) YYABORT;}
                        ;
opt_attr_list           : ',' id_comma_list
			| 
			;
bool_def                : BOOL identifier bool_val ';'
                        { if (define_bool_tunable(0)) YYABORT; }
                        ;
tunable_def		: TUNABLE identifier bool_val ';'
			{ if (define_bool_tunable(1)) YYABORT; }
			;
bool_val                : CTRUE
			{ if (insert_id("T",0)) YYABORT; }
                        | CFALSE
			{ if (insert_id("F",0)) YYABORT; }
                        ;
cond_stmt_def           : IF cond_expr '{' cond_pol_list '}' cond_else
                        { if (pass == 2) { if (define_conditional((cond_expr_t*)$2, (avrule_t*)$4, (avrule_t*)$6) < 0) YYABORT;  }}
                        ;
cond_else		: ELSE '{' cond_pol_list '}'
			{ $$ = $3; }
			| /* empty */ 
			{ $$ = NULL; }
			;
cond_expr               : '(' cond_expr ')'
			{ $$ = $2;}
			| NOT cond_expr
			{ $$ = define_cond_expr(COND_NOT, $2, 0);
			  if ($$ == 0) YYABORT; }
			| cond_expr AND cond_expr
			{ $$ = define_cond_expr(COND_AND, $1, $3);
			  if ($$ == 0) YYABORT; }
			| cond_expr OR cond_expr
			{ $$ = define_cond_expr(COND_OR, $1, $3);
			  if ($$ == 0) YYABORT; }
			| cond_expr XOR cond_expr
			{ $$ = define_cond_expr(COND_XOR, $1, $3);
			  if ($$ == 0) YYABORT; }
			| cond_expr EQUALS cond_expr
			{ $$ = define_cond_expr(COND_EQ, $1, $3);
			  if ($$ == 0) YYABORT; }
			| cond_expr NOTEQUAL cond_expr
			{ $$ = define_cond_expr(COND_NEQ, $1, $3);
			  if ($$ == 0) YYABORT; }
			| cond_expr_prim
			{ $$ = $1; }
			;
cond_expr_prim          : identifier
                        { $$ = define_cond_expr(COND_BOOL,0, 0);
			  if ($$ == COND_ERR) YYABORT; }
                        ;
cond_pol_list           : cond_pol_list cond_rule_def 
                        { $$ = define_cond_pol_list((avrule_t *)$1, (avrule_t *)$2); }
			| /* empty */ 
			{ $$ = NULL; }
			;
cond_rule_def           : cond_transition_def
                        { $$ = $1; }
                        | cond_te_avtab_def
                        { $$ = $1; }
			| require_block
			{ $$ = NULL; }
                        ;
cond_transition_def	: TYPE_TRANSITION names names ':' names identifier filename ';'
                        { $$ = define_cond_filename_trans() ;
                          if ($$ == COND_ERR) YYABORT;}
			| TYPE_TRANSITION names names ':' names identifier ';'
                        { $$ = define_cond_compute_type(AVRULE_TRANSITION) ;
                          if ($$ == COND_ERR) YYABORT;}
                        | TYPE_MEMBER names names ':' names identifier ';'
                        { $$ = define_cond_compute_type(AVRULE_MEMBER) ;
                          if ($$ ==  COND_ERR) YYABORT;}
                        | TYPE_CHANGE names names ':' names identifier ';'
                        { $$ = define_cond_compute_type(AVRULE_CHANGE) ;
                          if ($$ == COND_ERR) YYABORT;}
    			;
cond_te_avtab_def	: cond_allow_def
                          { $$ = $1; }
			| cond_auditallow_def
			  { $$ = $1; }
			| cond_auditdeny_def
			  { $$ = $1; }
			| cond_dontaudit_def
			  { $$ = $1; }
			| cond_xperm_allow_def
			  { $$ = $1; }
			| cond_xperm_auditallow_def
			  { $$ = $1; }
			| cond_xperm_dontaudit_def
			  { $$ = $1; }
			;
cond_allow_def		: ALLOW names names ':' names names  ';'
			{ $$ = define_cond_te_avtab(AVRULE_ALLOWED) ;
                          if ($$ == COND_ERR) YYABORT; }
		        ;
cond_auditallow_def	: AUDITALLOW names names ':' names names ';'
			{ $$ = define_cond_te_avtab(AVRULE_AUDITALLOW) ;
                          if ($$ == COND_ERR) YYABORT; }
		        ;
cond_auditdeny_def	: AUDITDENY names names ':' names names ';'
			{ $$ = define_cond_te_avtab(AVRULE_AUDITDENY) ;
                          if ($$ == COND_ERR) YYABORT; }
		        ;
cond_dontaudit_def	: DONTAUDIT names names ':' names names ';'
			{ $$ = define_cond_te_avtab(AVRULE_DONTAUDIT);
                          if ($$ == COND_ERR) YYABORT; }
		        ;
cond_xperm_allow_def		: ALLOWXPERM names names ':' names identifier xperms ';'
				{ $$ = define_cond_te_avtab_extended_perms(AVRULE_XPERMS_ALLOWED) ;
				  if ($$ == COND_ERR) YYABORT; }
				;
cond_xperm_auditallow_def	: AUDITALLOWXPERM names names ':' names identifier xperms ';'
				{ $$ = define_cond_te_avtab_extended_perms(AVRULE_XPERMS_AUDITALLOW) ;
				  if ($$ == COND_ERR) YYABORT; }
				;
cond_xperm_dontaudit_def	: DONTAUDITXPERM names names ':' names identifier xperms ';'
				{ $$ = define_cond_te_avtab_extended_perms(AVRULE_XPERMS_DONTAUDIT) ;
				  if ($$ == COND_ERR) YYABORT; }
				;
transition_def		: TYPE_TRANSITION  names names ':' names identifier filename ';'
			{if (define_filename_trans()) YYABORT; }
			| TYPE_TRANSITION names names ':' names identifier ';'
                        {if (define_compute_type(AVRULE_TRANSITION)) YYABORT;}
                        | TYPE_MEMBER names names ':' names identifier ';'
                        {if (define_compute_type(AVRULE_MEMBER)) YYABORT;}
                        | TYPE_CHANGE names names ':' names identifier ';'
                        {if (define_compute_type(AVRULE_CHANGE)) YYABORT;}
    			;
range_trans_def		: RANGE_TRANSITION names names mls_range_def ';'
			{ if (define_range_trans(0)) YYABORT; }
			| RANGE_TRANSITION names names ':' names mls_range_def ';'
			{ if (define_range_trans(1)) YYABORT; }
			;
te_avtab_def		: allow_def
			| auditallow_def
			| auditdeny_def
			| dontaudit_def
			| neverallow_def
			| xperm_allow_def
			| xperm_auditallow_def
			| xperm_dontaudit_def
			| xperm_neverallow_def
			;
allow_def		: ALLOW names names ':' names names  ';'
			{if (define_te_avtab(AVRULE_ALLOWED)) YYABORT; }
		        ;
auditallow_def		: AUDITALLOW names names ':' names names ';'
			{if (define_te_avtab(AVRULE_AUDITALLOW)) YYABORT; }
		        ;
auditdeny_def		: AUDITDENY names names ':' names names ';'
			{if (define_te_avtab(AVRULE_AUDITDENY)) YYABORT; }
		        ;
dontaudit_def		: DONTAUDIT names names ':' names names ';'
			{if (define_te_avtab(AVRULE_DONTAUDIT)) YYABORT; }
		        ;
neverallow_def		: NEVERALLOW names names ':' names names  ';'
			{if (define_te_avtab(AVRULE_NEVERALLOW)) YYABORT; }
		        ;
xperm_allow_def		: ALLOWXPERM names names ':' names identifier xperms ';'
			{if (define_te_avtab_extended_perms(AVRULE_XPERMS_ALLOWED)) YYABORT; }
		        ;
xperm_auditallow_def	: AUDITALLOWXPERM names names ':' names identifier xperms ';'
			{if (define_te_avtab_extended_perms(AVRULE_XPERMS_AUDITALLOW)) YYABORT; }
		        ;
xperm_dontaudit_def	: DONTAUDITXPERM names names ':' names identifier xperms ';'
			{if (define_te_avtab_extended_perms(AVRULE_XPERMS_DONTAUDIT)) YYABORT; }
		        ;
xperm_neverallow_def	: NEVERALLOWXPERM names names ':' names identifier xperms ';'
			{if (define_te_avtab_extended_perms(AVRULE_XPERMS_NEVERALLOW)) YYABORT; }
		        ;
attribute_role_def	: ATTRIBUTE_ROLE identifier ';'
			{if (define_attrib_role()) YYABORT; }
		        ;
role_type_def		: ROLE identifier TYPES names ';'
			{if (define_role_types()) YYABORT;}
			;
role_attr_def		: ROLE identifier opt_attr_list ';'
			{if (define_role_attr()) YYABORT;}
                        ;
role_trans_def		: ROLE_TRANSITION names names identifier ';'
			{if (define_role_trans(0)) YYABORT; }
			| ROLE_TRANSITION names names ':' names identifier ';'
			{if (define_role_trans(1)) YYABORT;}
			;
role_allow_def		: ALLOW names names ';'
			{if (define_role_allow()) YYABORT; }
			;
roleattribute_def	: ROLEATTRIBUTE identifier id_comma_list ';'
			{if (define_roleattribute()) YYABORT;}
			;
opt_constraints         : constraints
                        |
                        ;
constraints		: constraint_decl
			| constraints constraint_decl
			;
constraint_decl		: constraint_def
			| validatetrans_def
			;
constraint_def		: CONSTRAIN names names cexpr ';'
			{ if (define_constraint((constraint_expr_t*)$4)) YYABORT; }
			;
validatetrans_def	: VALIDATETRANS names cexpr ';'
			{ if (define_validatetrans((constraint_expr_t*)$3)) YYABORT; }
			;
cexpr			: '(' cexpr ')'
			{ $$ = $2; }
			| NOT cexpr
			{ $$ = define_cexpr(CEXPR_NOT, $2, 0);
			  if ($$ == 0) YYABORT; }
			| cexpr AND cexpr
			{ $$ = define_cexpr(CEXPR_AND, $1, $3);
			  if ($$ == 0) YYABORT; }
			| cexpr OR cexpr
			{ $$ = define_cexpr(CEXPR_OR, $1, $3);
			  if ($$ == 0) YYABORT; }
			| cexpr_prim
			{ $$ = $1; }
			;
cexpr_prim		: U1 op U2
			{ $$ = define_cexpr(CEXPR_ATTR, CEXPR_USER, $2);
			  if ($$ == 0) YYABORT; }
			| R1 role_mls_op R2
			{ $$ = define_cexpr(CEXPR_ATTR, CEXPR_ROLE, $2);
			  if ($$ == 0) YYABORT; }
			| T1 op T2
			{ $$ = define_cexpr(CEXPR_ATTR, CEXPR_TYPE, $2);
			  if ($$ == 0) YYABORT; }
			| U1 op { if (insert_separator(1)) YYABORT; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, CEXPR_USER, $2);
			  if ($$ == 0) YYABORT; }
			| U2 op { if (insert_separator(1)) YYABORT; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, (CEXPR_USER | CEXPR_TARGET), $2);
			  if ($$ == 0) YYABORT; }
			| U3 op { if (insert_separator(1)) YYABORT; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, (CEXPR_USER | CEXPR_XTARGET), $2);
			  if ($$ == 0) YYABORT; }
			| R1 op { if (insert_separator(1)) YYABORT; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, CEXPR_ROLE, $2);
			  if ($$ == 0) YYABORT; }
			| R2 op { if (insert_separator(1)) YYABORT; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, (CEXPR_ROLE | CEXPR_TARGET), $2);
			  if ($$ == 0) YYABORT; }
			| R3 op { if (insert_separator(1)) YYABORT; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, (CEXPR_ROLE | CEXPR_XTARGET), $2);
			  if ($$ == 0) YYABORT; }
			| T1 op { if (insert_separator(1)) YYABORT; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, CEXPR_TYPE, $2);
			  if ($$ == 0) YYABORT; }
			| T2 op { if (insert_separator(1)) YYABORT; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, (CEXPR_TYPE | CEXPR_TARGET), $2);
			  if ($$ == 0) YYABORT; }
			| T3 op { if (insert_separator(1)) YYABORT; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, (CEXPR_TYPE | CEXPR_XTARGET), $2);
			  if ($$ == 0) YYABORT; }
			| SAMEUSER
			{ $$ = define_cexpr(CEXPR_ATTR, CEXPR_USER, CEXPR_EQ);
			  if ($$ == 0) YYABORT; }
			| SOURCE ROLE { if (insert_separator(1)) YYABORT; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, CEXPR_ROLE, CEXPR_EQ);
			  if ($$ == 0) YYABORT; }
			| TARGET ROLE { if (insert_separator(1)) YYABORT; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, (CEXPR_ROLE | CEXPR_TARGET), CEXPR_EQ);
			  if ($$ == 0) YYABORT; }
			| ROLE role_mls_op
			{ $$ = define_cexpr(CEXPR_ATTR, CEXPR_ROLE, $2);
			  if ($$ == 0) YYABORT; }
			| SOURCE TYPE { if (insert_separator(1)) YYABORT; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, CEXPR_TYPE, CEXPR_EQ);
			  if ($$ == 0) YYABORT; }
			| TARGET TYPE { if (insert_separator(1)) YYABORT; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, (CEXPR_TYPE | CEXPR_TARGET), CEXPR_EQ);
			  if ($$ == 0) YYABORT; }
			| L1 role_mls_op L2
			{ $$ = define_cexpr(CEXPR_ATTR, CEXPR_L1L2, $2);
			  if ($$ == 0) YYABORT; }
			| L1 role_mls_op H2
			{ $$ = define_cexpr(CEXPR_ATTR, CEXPR_L1H2, $2);
			  if ($$ == 0) YYABORT; }
			| H1 role_mls_op L2
			{ $$ = define_cexpr(CEXPR_ATTR, CEXPR_H1L2, $2);
			  if ($$ == 0) YYABORT; }
			| H1 role_mls_op H2
			{ $$ = define_cexpr(CEXPR_ATTR, CEXPR_H1H2, $2);
			  if ($$ == 0) YYABORT; }
			| L1 role_mls_op H1
			{ $$ = define_cexpr(CEXPR_ATTR, CEXPR_L1H1, $2);
			  if ($$ == 0) YYABORT; }
			| L2 role_mls_op H2
			{ $$ = define_cexpr(CEXPR_ATTR, CEXPR_L2H2, $2);
			  if ($$ == 0) YYABORT; }
			;
op			: EQUALS
			{ $$ = CEXPR_EQ; }
			| NOTEQUAL
			{ $$ = CEXPR_NEQ; }
			;
role_mls_op		: op
			{ $$ = $1; }
			| DOM
			{ $$ = CEXPR_DOM; }
			| DOMBY
			{ $$ = CEXPR_DOMBY; }
			| INCOMP
			{ $$ = CEXPR_INCOMP; }
			;
users			: user_def
			| users user_def
			;
user_def		: USER identifier ROLES names opt_mls_user ';'
	                {if (define_user()) YYABORT;}
			;
opt_mls_user		: LEVEL mls_level_def RANGE mls_range_def
			|
			;
initial_sid_contexts	: initial_sid_context_def
			| initial_sid_contexts initial_sid_context_def
			;
initial_sid_context_def	: SID identifier security_context_def
			{if (define_initial_sid_context()) YYABORT;}
			;
opt_dev_contexts	: dev_contexts |
			;
dev_contexts		: dev_context_def
			| dev_contexts dev_context_def
			;
dev_context_def		: pirq_context_def |
			  iomem_context_def |
			  ioport_context_def |
			  pci_context_def |
			  dtree_context_def
			;
pirq_context_def 	: PIRQCON number security_context_def
		        {if (define_pirq_context($2)) YYABORT;}
		        ;
iomem_context_def	: IOMEMCON number64 security_context_def
		        {if (define_iomem_context($2,$2)) YYABORT;}
		        | IOMEMCON number64 '-' number64 security_context_def
		        {if (define_iomem_context($2,$4)) YYABORT;}
		        ;
ioport_context_def	: IOPORTCON number security_context_def
			{if (define_ioport_context($2,$2)) YYABORT;}
			| IOPORTCON number '-' number security_context_def
			{if (define_ioport_context($2,$4)) YYABORT;}
			;
pci_context_def  	: PCIDEVICECON number security_context_def
		        {if (define_pcidevice_context($2)) YYABORT;}
		        ;
dtree_context_def	: DEVICETREECON path security_context_def
		        {if (define_devicetree_context()) YYABORT;}
		        ;
opt_fs_contexts         : fs_contexts 
                        |
                        ;
fs_contexts		: fs_context_def
			| fs_contexts fs_context_def
			;
fs_context_def		: FSCON number number security_context_def security_context_def
			{if (define_fs_context($2,$3)) YYABORT;}
			;
net_contexts		: opt_port_contexts opt_netif_contexts opt_node_contexts
			;
opt_port_contexts       : port_contexts
                        |
                        ;
port_contexts		: port_context_def
			| port_contexts port_context_def
			;
port_context_def	: PORTCON identifier number security_context_def
			{if (define_port_context($3,$3)) YYABORT;}
			| PORTCON identifier number '-' number security_context_def
			{if (define_port_context($3,$5)) YYABORT;}
			;
opt_ibpkey_contexts     : ibpkey_contexts
                        |
                        ;
ibpkey_contexts		: ibpkey_context_def
			| ibpkey_contexts ibpkey_context_def
			;
ibpkey_context_def	: IBPKEYCON ipv6_addr number security_context_def
			{if (define_ibpkey_context($3,$3)) YYABORT;}
			| IBPKEYCON ipv6_addr number '-' number security_context_def
			{if (define_ibpkey_context($3,$5)) YYABORT;}
			;
opt_ibendport_contexts	: ibendport_contexts
			|
			;
ibendport_contexts	: ibendport_context_def
                        | ibendport_contexts ibendport_context_def
                        ;
ibendport_context_def	: IBENDPORTCON identifier number security_context_def
                        {if (define_ibendport_context($3)) YYABORT;}
                        ;
opt_netif_contexts      : netif_contexts 
                        |
                        ;
netif_contexts		: netif_context_def
			| netif_contexts netif_context_def
			;
netif_context_def	: NETIFCON identifier security_context_def security_context_def
			{if (define_netif_context()) YYABORT;}
			;
opt_node_contexts       : node_contexts 
                        |
                        ;
node_contexts		: node_context_def
			| node_contexts node_context_def
			;
node_context_def	: NODECON ipv4_addr_def ipv4_addr_def security_context_def
			{if (define_ipv4_node_context()) YYABORT;}
			| NODECON ipv4_cidr_def security_context_def
			{if (define_ipv4_cidr_node_context()) YYABORT;}
			| NODECON ipv6_addr ipv6_addr security_context_def
			{if (define_ipv6_node_context()) YYABORT;}
			| NODECON ipv6_cidr security_context_def
			{if (define_ipv6_cidr_node_context()) YYABORT;}
			;
opt_fs_uses             : fs_uses
                        |
                        ;
fs_uses                 : fs_use_def
                        | fs_uses fs_use_def
                        ;
fs_use_def              : FSUSEXATTR filesystem security_context_def ';'
                        {if (define_fs_use(SECURITY_FS_USE_XATTR)) YYABORT;}
                        | FSUSETASK identifier security_context_def ';'
                        {if (define_fs_use(SECURITY_FS_USE_TASK)) YYABORT;}
                        | FSUSETRANS identifier security_context_def ';'
                        {if (define_fs_use(SECURITY_FS_USE_TRANS)) YYABORT;}
                        ;
opt_genfs_contexts      : genfs_contexts
                        |
                        ;
genfs_contexts          : genfs_context_def
                        | genfs_contexts genfs_context_def
                        ;
genfs_context_def	: GENFSCON filesystem path '-' identifier security_context_def
			{if (define_genfs_context(1)) YYABORT;}
			| GENFSCON filesystem path '-' '-' {insert_id("-", 0);} security_context_def
			{if (define_genfs_context(1)) YYABORT;}
                        | GENFSCON filesystem path security_context_def
			{if (define_genfs_context(0)) YYABORT;}
			;
ipv4_addr_def		: IPV4_ADDR
			{ if (insert_id(yytext,0)) YYABORT; }
			;
ipv4_cidr_def		: IPV4_CIDR
			{ if (insert_id(yytext,0)) YYABORT; }
			;
xperms		: xperm
			{ if (insert_separator(0)) YYABORT; }
			| nested_xperm_set
			{ if (insert_separator(0)) YYABORT; }
			| tilde xperm
                        { if (insert_id("~", 0)) YYABORT; }
			| tilde nested_xperm_set
			{ if (insert_id("~", 0)) YYABORT;
			  if (insert_separator(0)) YYABORT; }
			;
nested_xperm_set	: '{' nested_xperm_list '}'
			;
nested_xperm_list	: nested_xperm_element
			| nested_xperm_list nested_xperm_element
			;
nested_xperm_element: xperm '-' { if (insert_id("-", 0)) YYABORT; } xperm
			| xperm
			| nested_xperm_set
			;
xperm		: number
                        { if (insert_id(yytext,0)) YYABORT; }
			;
security_context_def	: identifier ':' identifier ':' identifier opt_mls_range_def
	                ;
opt_mls_range_def	: ':' mls_range_def
			|	
			;
mls_range_def		: mls_level_def '-' mls_level_def
			{if (insert_separator(0)) YYABORT;}
	                | mls_level_def
			{if (insert_separator(0)) YYABORT;}
	                ;
mls_level_def		: identifier ':' id_comma_list
			{if (insert_separator(0)) YYABORT;}
	                | identifier
			{if (insert_separator(0)) YYABORT;}
	                ;
id_comma_list           : identifier
			| id_comma_list ',' identifier
			;
tilde			: '~'
			;
asterisk		: '*'
			;
names           	: identifier
			{ if (insert_separator(0)) YYABORT; }
			| nested_id_set
			{ if (insert_separator(0)) YYABORT; }
			| asterisk
                        { if (insert_id("*", 0)) YYABORT;
			  if (insert_separator(0)) YYABORT; }
			| tilde identifier
                        { if (insert_id("~", 0)) YYABORT;
			  if (insert_separator(0)) YYABORT; }
			| tilde nested_id_set
			{ if (insert_id("~", 0)) YYABORT;
			  if (insert_separator(0)) YYABORT; }
                        | identifier '-' { if (insert_id("-", 0)) YYABORT; } identifier
			{ if (insert_separator(0)) YYABORT; }
			;
tilde_push              : tilde
                        { if (insert_id("~", 1)) YYABORT; }
			;
asterisk_push           : asterisk
                        { if (insert_id("*", 1)) YYABORT; }
			;
names_push		: identifier_push
			| '{' identifier_list_push '}'
			| asterisk_push
			| tilde_push identifier_push
			| tilde_push '{' identifier_list_push '}'
			;
identifier_list_push	: identifier_push
			| identifier_list_push identifier_push
			;
identifier_push		: IDENTIFIER
			{ if (insert_id(yytext, 1)) YYABORT; }
			;
identifier_list		: identifier
			| identifier_list identifier
			;
nested_id_set           : '{' nested_id_list '}'
                        ;
nested_id_list          : nested_id_element | nested_id_list nested_id_element
                        ;
nested_id_element       : identifier | '-' { if (insert_id("-", 0)) YYABORT; } identifier | nested_id_set
                        ;
identifier		: IDENTIFIER
			{ if (insert_id(yytext,0)) YYABORT; }
			;
filesystem		: FILESYSTEM
                        { if (insert_id(yytext,0)) YYABORT; }
                        | IDENTIFIER
			{ if (insert_id(yytext,0)) YYABORT; }
                        ;
path     		: PATH
			{ if (insert_id(yytext,0)) YYABORT; }
			| QPATH
			{ yytext[strlen(yytext) - 1] = '\0'; if (insert_id(yytext + 1,0)) YYABORT; }
			;
filename		: FILENAME
			{ yytext[strlen(yytext) - 1] = '\0'; if (insert_id(yytext + 1,0)) YYABORT; }
			;
number			: NUMBER 
			{ unsigned long x;
			  errno = 0;
			  x = strtoul(yytext, NULL, 0);
			  if (errno)
			      YYABORT;
#if ULONG_MAX > UINT_MAX
			  if (x > UINT_MAX)
			      YYABORT;
#endif
			  $$ = (unsigned int) x;
			}
			;
number64		: NUMBER
			{ unsigned long long x;
			  errno = 0;
			  x = strtoull(yytext, NULL, 0);
			  if (errno)
			      YYABORT;
			  $$ = (uint64_t) x;
			}
			;
ipv6_addr		: IPV6_ADDR
			{ if (insert_id(yytext,0)) YYABORT; }
			;
ipv6_cidr		: IPV6_CIDR
			{ if (insert_id(yytext,0)) YYABORT; }
			;
policycap_def		: POLICYCAP identifier ';'
			{if (define_polcap()) YYABORT;}
			;
permissive_def		: PERMISSIVE identifier ';'
			{if (define_permissive()) YYABORT;}
neveraudit_def		: NEVERAUDIT identifier ';'
			{if (define_neveraudit()) YYABORT;}

/*********** module grammar below ***********/

module_policy           : module_def avrules_block
                        { if (end_avrule_block(pass) == -1) YYABORT;
                          if (policydb_index_others(NULL, policydbp, 0)) YYABORT;
                        }
                        ;
module_def              : MODULE identifier version_identifier ';'
                        { if (define_policy(pass, 1) == -1) YYABORT; }
                        ;
version_identifier      : VERSION_IDENTIFIER
                        { if (insert_id(yytext,0)) YYABORT; }
			| number
                        { if (insert_id(yytext,0)) YYABORT; }
                        | ipv4_addr_def /* version can look like ipv4 address */
                        ;
avrules_block           : avrule_decls avrule_user_defs
                        ;
avrule_decls            : avrule_decls avrule_decl
                        | avrule_decl
                        ;
avrule_decl             : rbac_decl
                        | te_decl
                        | cond_stmt_def
                        | require_block
                        | optional_block
                        | ';'
                        ;
require_block           : REQUIRE '{' require_list '}'
                        ;
require_list            : require_list require_decl
                        | require_decl
                        ;
require_decl            : require_class ';'
                        | require_decl_def require_id_list ';'
                        ;
require_class           : CLASS identifier names
                        { if (require_class(pass)) YYABORT; }
                        ;
require_decl_def        : ROLE        { $$ = require_role; }
                        | TYPE        { $$ = require_type; }
                        | ATTRIBUTE   { $$ = require_attribute; }
                        | ATTRIBUTE_ROLE   { $$ = require_attribute_role; }
                        | USER        { $$ = require_user; }
                        | BOOL        { $$ = require_bool; }
			| TUNABLE     { $$ = require_tunable; }
                        | SENSITIVITY { $$ = require_sens; }
                        | CATEGORY    { $$ = require_cat; }
                        ;
require_id_list         : identifier
                        { if ($<require_func>0 (pass)) YYABORT; }
                        | require_id_list ',' identifier
                        { if ($<require_func>0 (pass)) YYABORT; }
                        ;
optional_block          : optional_decl '{' avrules_block '}'
                        { if (end_avrule_block(pass) == -1) YYABORT; }
                          optional_else
                        { if (end_optional(pass) == -1) YYABORT; }
                        ;
optional_else           : else_decl '{' avrules_block '}'
                        { if (end_avrule_block(pass) == -1) YYABORT; }
                        | /* empty */
                        ;
optional_decl           : OPTIONAL
                        { if (begin_optional(pass) == -1) YYABORT; }
                        ;
else_decl               : ELSE
                        { if (begin_optional_else(pass) == -1) YYABORT; }
                        ;
avrule_user_defs        : user_def avrule_user_defs
                        | /* empty */
                        ;
