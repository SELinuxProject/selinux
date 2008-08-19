
/*
 * Author : Stephen Smalley, <sds@epoch.ncsc.mil> 
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
 *	    Karl MacMillan <kmacmillan@tresys.com>
 *          Jason Tang     <jtang@tresys.com>
 *
 *	Added support for binary policy modules
 *
 * Copyright (C) 2004-2005 Trusted Computer Solutions, Inc.
 * Copyright (C) 2003 - 2005 Tresys Technology, LLC
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
#include <sepol/policydb/flask.h>
#include <sepol/policydb/hierarchy.h>
#include "queue.h"
#include "checkpolicy.h"
#include "module_compiler.h"

/* 
 * We need the following so we have a valid error return code in yacc
 * when we have a parse error for a conditional rule.  We can't check 
 * for NULL (ie 0) because that is a potentially valid return.
 */
static avrule_t *conditional_unused_error_code;
#define COND_ERR (avrule_t *)&conditional_unused_error_code

#define TRUE 1
#define FALSE 0

policydb_t *policydbp;
queue_t id_queue = 0;
static unsigned int pass;
char *curfile = 0;
int mlspol = 0;
int handle_unknown = 0;

extern unsigned long policydb_lineno;
extern unsigned long source_lineno;
extern unsigned int policydb_errors;
extern unsigned int policyvers;

extern char yytext[];
extern int yylex(void);
extern int yywarn(char *msg);
extern int yyerror(char *msg);

#define ERRORMSG_LEN 255
static char errormsg[ERRORMSG_LEN + 1] = {0};

static int insert_separator(int push);
static int insert_id(char *id,int push);
static int id_has_dot(char *id);
static int define_class(void);
static int define_initial_sid(void);
static int define_common_perms(void);
static int define_av_perms(int inherits);
static int define_sens(void);
static int define_dominance(void);
static int define_category(void);
static int define_level(void);
static int define_attrib(void);
static int define_typealias(void);
static int define_typeattribute(void);
static int define_type(int alias);
static int define_compute_type(int which);
static int define_te_avtab(int which);
static int define_role_types(void);
static role_datum_t *merge_roles_dom(role_datum_t *r1,role_datum_t *r2);
static role_datum_t *define_role_dom(role_datum_t *r);
static int define_role_trans(void);
static int define_range_trans(int class_specified);
static int define_role_allow(void);
static int define_constraint(constraint_expr_t *expr);
static int define_validatetrans(constraint_expr_t *expr);
static int define_bool(void);
static int define_conditional(cond_expr_t *expr, avrule_t *t_list, avrule_t *f_list );
static cond_expr_t *define_cond_expr(uint32_t expr_type, void *arg1, void* arg2);
static avrule_t *define_cond_pol_list(avrule_t *avlist, avrule_t *stmt);
static avrule_t *define_cond_compute_type(int which);
static avrule_t *define_cond_te_avtab(int which);
static uintptr_t define_cexpr(uint32_t expr_type, uintptr_t arg1, uintptr_t arg2);
static int define_user(void);
static int parse_security_context(context_struct_t *c);
static int define_initial_sid_context(void);
static int define_fs_use(int behavior);
static int define_genfs_context(int has_type);
static int define_fs_context(unsigned int major, unsigned int minor);
static int define_port_context(unsigned int low, unsigned int high);
static int define_netif_context(void);
static int define_ipv4_node_context(void);
static int define_ipv6_node_context(void);

typedef int (* require_func_t)();

%}

%union {
	unsigned int val;
	uintptr_t valptr;
	void *ptr;
        require_func_t require_func;
}

%type <ptr> cond_expr cond_expr_prim cond_pol_list cond_else
%type <ptr> cond_allow_def cond_auditallow_def cond_auditdeny_def cond_dontaudit_def
%type <ptr> cond_transition_def cond_te_avtab_def cond_rule_def
%type <ptr> role_def roles
%type <valptr> cexpr cexpr_prim op role_mls_op
%type <val> ipv4_addr_def number
%type <require_func> require_decl_def

%token PATH
%token CLONE
%token COMMON
%token CLASS
%token CONSTRAIN
%token VALIDATETRANS
%token INHERITS
%token SID
%token ROLE
%token ROLES
%token TYPEALIAS
%token TYPEATTRIBUTE
%token TYPE
%token TYPES
%token ALIAS
%token ATTRIBUTE
%token BOOL
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
%token SOURCE
%token TARGET
%token SAMEUSER
%token FSCON PORTCON NETIFCON NODECON 
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
%token IPV6_ADDR
%token MODULE VERSION_IDENTIFIER REQUIRE OPTIONAL

%left OR
%left XOR
%left AND
%right NOT
%left EQUALS NOTEQUAL
%%
policy			: base_policy
                        | module_policy
                        ;
base_policy             : { if (define_policy(pass, 0) == -1) return -1; }
                          classes initial_sids access_vectors
                          { if (pass == 1) { if (policydb_index_classes(policydbp)) return -1; }
                            else if (pass == 2) { if (policydb_index_others(NULL, policydbp, 0)) return -1; }}
			  opt_mls te_rbac users opt_constraints 
                         { if (pass == 1) { if (policydb_index_bools(policydbp)) return -1;}
			   else if (pass == 2) { if (policydb_index_others(NULL, policydbp, 0)) return -1;}}
			  initial_sid_contexts opt_fs_contexts opt_fs_uses opt_genfs_contexts net_contexts 
			;
classes			: class_def 
			| classes class_def
			;
class_def		: CLASS identifier
			{if (define_class()) return -1;}
			;
initial_sids 		: initial_sid_def 
			| initial_sids initial_sid_def
			;
initial_sid_def		: SID identifier
                        {if (define_initial_sid()) return -1;}
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
			{if (define_common_perms()) return -1;}
			;
av_perms		: av_perms_def
			| av_perms av_perms_def
			;
av_perms_def		: CLASS identifier '{' identifier_list '}'
			{if (define_av_perms(FALSE)) return -1;}
                        | CLASS identifier INHERITS identifier 
			{if (define_av_perms(TRUE)) return -1;}
                        | CLASS identifier INHERITS identifier '{' identifier_list '}'
			{if (define_av_perms(TRUE)) return -1;}
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
			{if (define_sens()) return -1;}
			| SENSITIVITY identifier ';'
			{if (define_sens()) return -1;}
	                ;
alias_def		: ALIAS names
			;
dominance		: DOMINANCE identifier 
			{if (define_dominance()) return -1;}
                        | DOMINANCE '{' identifier_list '}' 
			{if (define_dominance()) return -1;}
			;
opt_categories          : categories
                        |
                        ;
categories 		: category_def 
			| categories category_def
			;
category_def		: CATEGORY identifier alias_def ';'
			{if (define_category()) return -1;}
			| CATEGORY identifier ';'
			{if (define_category()) return -1;}
			;
levels	 		: level_def 
			| levels level_def
			;
level_def		: LEVEL identifier ':' id_comma_list ';'
			{if (define_level()) return -1;}
			| LEVEL identifier ';' 
			{if (define_level()) return -1;}
			;
mlspolicy		: mlspolicy_decl
			| mlspolicy mlspolicy_decl
			;
mlspolicy_decl		: mlsconstraint_def
			| mlsvalidatetrans_def
			;
mlsconstraint_def	: MLSCONSTRAIN names names cexpr ';'
			{ if (define_constraint((constraint_expr_t*)$4)) return -1; }
			;
mlsvalidatetrans_def	: MLSVALIDATETRANS names cexpr ';'
			{ if (define_validatetrans((constraint_expr_t*)$3)) return -1; }
			;
te_rbac			: te_rbac_decl
			| te_rbac te_rbac_decl
			;
te_rbac_decl		: te_decl
			| rbac_decl
                        | cond_stmt_def
			| optional_block
			| ';'
                        ;
rbac_decl		: role_type_def
                        | role_dominance
                        | role_trans_def
 			| role_allow_def
			;
te_decl			: attribute_def
                        | type_def
                        | typealias_def
                        | typeattribute_def
                        | bool_def
                        | transition_def
                        | range_trans_def
                        | te_avtab_def
			;
attribute_def           : ATTRIBUTE identifier ';'
                        { if (define_attrib()) return -1;}
                        ;
type_def		: TYPE identifier alias_def opt_attr_list ';'
                        {if (define_type(1)) return -1;}
	                | TYPE identifier opt_attr_list ';'
                        {if (define_type(0)) return -1;}
    			;
typealias_def           : TYPEALIAS identifier alias_def ';'
			{if (define_typealias()) return -1;}
			;
typeattribute_def	: TYPEATTRIBUTE identifier id_comma_list ';'
			{if (define_typeattribute()) return -1;}
			;
opt_attr_list           : ',' id_comma_list
			| 
			;
bool_def                : BOOL identifier bool_val ';'
                        {if (define_bool()) return -1;}
                        ;
bool_val                : CTRUE
 			{ if (insert_id("T",0)) return -1; }
                        | CFALSE
			{ if (insert_id("F",0)) return -1; }
                        ;
cond_stmt_def           : IF cond_expr '{' cond_pol_list '}' cond_else
                        { if (pass == 2) { if (define_conditional((cond_expr_t*)$2, (avrule_t*)$4, (avrule_t*)$6) < 0) return -1;  }}
                        ;
cond_else		: ELSE '{' cond_pol_list '}'
			{ $$ = $3; }
			| /* empty */ 
			{ $$ = NULL; }
cond_expr               : '(' cond_expr ')'
			{ $$ = $2;}
			| NOT cond_expr
			{ $$ = define_cond_expr(COND_NOT, $2, 0);
			  if ($$ == 0) return -1; }
			| cond_expr AND cond_expr
			{ $$ = define_cond_expr(COND_AND, $1, $3);
			  if ($$ == 0) return  -1; }
			| cond_expr OR cond_expr
			{ $$ = define_cond_expr(COND_OR, $1, $3);
			  if ($$ == 0) return   -1; }
			| cond_expr XOR cond_expr
			{ $$ = define_cond_expr(COND_XOR, $1, $3);
			  if ($$ == 0) return  -1; }
			| cond_expr EQUALS cond_expr
			{ $$ = define_cond_expr(COND_EQ, $1, $3);
			  if ($$ == 0) return  -1; }
			| cond_expr NOTEQUAL cond_expr
			{ $$ = define_cond_expr(COND_NEQ, $1, $3);
			  if ($$ == 0) return  -1; }
			| cond_expr_prim
			{ $$ = $1; }
			;
cond_expr_prim          : identifier
                        { $$ = define_cond_expr(COND_BOOL,0, 0);
			  if ($$ == COND_ERR) return   -1; }
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
cond_transition_def	: TYPE_TRANSITION names names ':' names identifier ';'
                        { $$ = define_cond_compute_type(AVRULE_TRANSITION) ;
                          if ($$ == COND_ERR) return -1;}
                        | TYPE_MEMBER names names ':' names identifier ';'
                        { $$ = define_cond_compute_type(AVRULE_MEMBER) ;
                          if ($$ ==  COND_ERR) return -1;}
                        | TYPE_CHANGE names names ':' names identifier ';'
                        { $$ = define_cond_compute_type(AVRULE_CHANGE) ;
                          if ($$ == COND_ERR) return -1;}
    			;
cond_te_avtab_def	: cond_allow_def
                          { $$ = $1; }
			| cond_auditallow_def
			  { $$ = $1; }
			| cond_auditdeny_def
			  { $$ = $1; }
			| cond_dontaudit_def
			  { $$ = $1; }
			;
cond_allow_def		: ALLOW names names ':' names names  ';'
			{ $$ = define_cond_te_avtab(AVRULE_ALLOWED) ;
                          if ($$ == COND_ERR) return -1; }
		        ;
cond_auditallow_def	: AUDITALLOW names names ':' names names ';'
			{ $$ = define_cond_te_avtab(AVRULE_AUDITALLOW) ;
                          if ($$ == COND_ERR) return -1; }
		        ;
cond_auditdeny_def	: AUDITDENY names names ':' names names ';'
			{ $$ = define_cond_te_avtab(AVRULE_AUDITDENY) ;
                          if ($$ == COND_ERR) return -1; }
		        ;
cond_dontaudit_def	: DONTAUDIT names names ':' names names ';'
			{ $$ = define_cond_te_avtab(AVRULE_DONTAUDIT);
                          if ($$ == COND_ERR) return -1; }
		        ;
transition_def		: TYPE_TRANSITION names names ':' names identifier ';'
                        {if (define_compute_type(AVRULE_TRANSITION)) return -1;}
                        | TYPE_MEMBER names names ':' names identifier ';'
                        {if (define_compute_type(AVRULE_MEMBER)) return -1;}
                        | TYPE_CHANGE names names ':' names identifier ';'
                        {if (define_compute_type(AVRULE_CHANGE)) return -1;}
    			;
range_trans_def		: RANGE_TRANSITION names names mls_range_def ';'
			{ if (define_range_trans(0)) return -1; }
			| RANGE_TRANSITION names names ':' names mls_range_def ';'
			{ if (define_range_trans(1)) return -1; }
			;
te_avtab_def		: allow_def
			| auditallow_def
			| auditdeny_def
			| dontaudit_def
			| neverallow_def
			;
allow_def		: ALLOW names names ':' names names  ';'
			{if (define_te_avtab(AVRULE_ALLOWED)) return -1; }
		        ;
auditallow_def		: AUDITALLOW names names ':' names names ';'
			{if (define_te_avtab(AVRULE_AUDITALLOW)) return -1; }
		        ;
auditdeny_def		: AUDITDENY names names ':' names names ';'
			{if (define_te_avtab(AVRULE_AUDITDENY)) return -1; }
		        ;
dontaudit_def		: DONTAUDIT names names ':' names names ';'
			{if (define_te_avtab(AVRULE_DONTAUDIT)) return -1; }
		        ;
neverallow_def		: NEVERALLOW names names ':' names names  ';'
			{if (define_te_avtab(AVRULE_NEVERALLOW)) return -1; }
		        ;
role_type_def		: ROLE identifier TYPES names ';'
			{if (define_role_types()) return -1;}
 			| ROLE identifier';'
 			{if (define_role_types()) return -1;}
                        ;
role_dominance		: DOMINANCE '{' roles '}'
			;
role_trans_def		: ROLE_TRANSITION names names identifier ';'
			{if (define_role_trans()) return -1; }
			;
role_allow_def		: ALLOW names names ';'
			{if (define_role_allow()) return -1; }
			;
roles			: role_def
			{ $$ = $1; }
			| roles role_def
			{ $$ = merge_roles_dom((role_datum_t*)$1, (role_datum_t*)$2); if ($$ == 0) return -1;}
			;
role_def		: ROLE identifier_push ';'
                        {$$ = define_role_dom(NULL); if ($$ == 0) return -1;}
			| ROLE identifier_push '{' roles '}'
                        {$$ = define_role_dom((role_datum_t*)$4); if ($$ == 0) return -1;}
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
			{ if (define_constraint((constraint_expr_t*)$4)) return -1; }
			;
validatetrans_def	: VALIDATETRANS names cexpr ';'
			{ if (define_validatetrans((constraint_expr_t*)$3)) return -1; }
			;
cexpr			: '(' cexpr ')'
			{ $$ = $2; }
			| NOT cexpr
			{ $$ = define_cexpr(CEXPR_NOT, $2, 0);
			  if ($$ == 0) return -1; }
			| cexpr AND cexpr
			{ $$ = define_cexpr(CEXPR_AND, $1, $3);
			  if ($$ == 0) return -1; }
			| cexpr OR cexpr
			{ $$ = define_cexpr(CEXPR_OR, $1, $3);
			  if ($$ == 0) return -1; }
			| cexpr_prim
			{ $$ = $1; }
			;
cexpr_prim		: U1 op U2
			{ $$ = define_cexpr(CEXPR_ATTR, CEXPR_USER, $2);
			  if ($$ == 0) return -1; }
			| R1 role_mls_op R2
			{ $$ = define_cexpr(CEXPR_ATTR, CEXPR_ROLE, $2);
			  if ($$ == 0) return -1; }
			| T1 op T2
			{ $$ = define_cexpr(CEXPR_ATTR, CEXPR_TYPE, $2);
			  if ($$ == 0) return -1; }
			| U1 op { if (insert_separator(1)) return -1; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, CEXPR_USER, $2);
			  if ($$ == 0) return -1; }
			| U2 op { if (insert_separator(1)) return -1; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, (CEXPR_USER | CEXPR_TARGET), $2);
			  if ($$ == 0) return -1; }
			| U3 op { if (insert_separator(1)) return -1; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, (CEXPR_USER | CEXPR_XTARGET), $2);
			  if ($$ == 0) return -1; }
			| R1 op { if (insert_separator(1)) return -1; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, CEXPR_ROLE, $2);
			  if ($$ == 0) return -1; }
			| R2 op { if (insert_separator(1)) return -1; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, (CEXPR_ROLE | CEXPR_TARGET), $2);
			  if ($$ == 0) return -1; }
			| R3 op { if (insert_separator(1)) return -1; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, (CEXPR_ROLE | CEXPR_XTARGET), $2);
			  if ($$ == 0) return -1; }
			| T1 op { if (insert_separator(1)) return -1; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, CEXPR_TYPE, $2);
			  if ($$ == 0) return -1; }
			| T2 op { if (insert_separator(1)) return -1; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, (CEXPR_TYPE | CEXPR_TARGET), $2);
			  if ($$ == 0) return -1; }
			| T3 op { if (insert_separator(1)) return -1; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, (CEXPR_TYPE | CEXPR_XTARGET), $2);
			  if ($$ == 0) return -1; }
			| SAMEUSER
			{ $$ = define_cexpr(CEXPR_ATTR, CEXPR_USER, CEXPR_EQ);
			  if ($$ == 0) return -1; }
			| SOURCE ROLE { if (insert_separator(1)) return -1; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, CEXPR_ROLE, CEXPR_EQ);
			  if ($$ == 0) return -1; }
			| TARGET ROLE { if (insert_separator(1)) return -1; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, (CEXPR_ROLE | CEXPR_TARGET), CEXPR_EQ);
			  if ($$ == 0) return -1; }
			| ROLE role_mls_op
			{ $$ = define_cexpr(CEXPR_ATTR, CEXPR_ROLE, $2);
			  if ($$ == 0) return -1; }
			| SOURCE TYPE { if (insert_separator(1)) return -1; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, CEXPR_TYPE, CEXPR_EQ);
			  if ($$ == 0) return -1; }
			| TARGET TYPE { if (insert_separator(1)) return -1; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, (CEXPR_TYPE | CEXPR_TARGET), CEXPR_EQ);
			  if ($$ == 0) return -1; }
			| L1 role_mls_op L2
			{ $$ = define_cexpr(CEXPR_ATTR, CEXPR_L1L2, $2);
			  if ($$ == 0) return -1; }
			| L1 role_mls_op H2
			{ $$ = define_cexpr(CEXPR_ATTR, CEXPR_L1H2, $2);
			  if ($$ == 0) return -1; }
			| H1 role_mls_op L2
			{ $$ = define_cexpr(CEXPR_ATTR, CEXPR_H1L2, $2);
			  if ($$ == 0) return -1; }
			| H1 role_mls_op H2
			{ $$ = define_cexpr(CEXPR_ATTR, CEXPR_H1H2, $2);
			  if ($$ == 0) return -1; }
			| L1 role_mls_op H1
			{ $$ = define_cexpr(CEXPR_ATTR, CEXPR_L1H1, $2);
			  if ($$ == 0) return -1; }
			| L2 role_mls_op H2
			{ $$ = define_cexpr(CEXPR_ATTR, CEXPR_L2H2, $2);
			  if ($$ == 0) return -1; }
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
	                {if (define_user()) return -1;}
			;
opt_mls_user		: LEVEL mls_level_def RANGE mls_range_def
			|
			;
initial_sid_contexts	: initial_sid_context_def
			| initial_sid_contexts initial_sid_context_def
			;
initial_sid_context_def	: SID identifier security_context_def
			{if (define_initial_sid_context()) return -1;}
			;
opt_fs_contexts         : fs_contexts 
                        |
                        ;
fs_contexts		: fs_context_def
			| fs_contexts fs_context_def
			;
fs_context_def		: FSCON number number security_context_def security_context_def
			{if (define_fs_context($2,$3)) return -1;}
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
			{if (define_port_context($3,$3)) return -1;}
			| PORTCON identifier number '-' number security_context_def
			{if (define_port_context($3,$5)) return -1;}
			;
opt_netif_contexts      : netif_contexts 
                        |
                        ;
netif_contexts		: netif_context_def
			| netif_contexts netif_context_def
			;
netif_context_def	: NETIFCON identifier security_context_def security_context_def
			{if (define_netif_context()) return -1;} 
			;
opt_node_contexts       : node_contexts 
                        |
                        ;
node_contexts		: node_context_def
			| node_contexts node_context_def
			;
node_context_def	: NODECON ipv4_addr_def ipv4_addr_def security_context_def
			{if (define_ipv4_node_context()) return -1;}
			| NODECON ipv6_addr ipv6_addr security_context_def
			{if (define_ipv6_node_context()) return -1;}
			;
opt_fs_uses             : fs_uses
                        |
                        ;
fs_uses                 : fs_use_def
                        | fs_uses fs_use_def
                        ;
fs_use_def              : FSUSEXATTR identifier security_context_def ';'
                        {if (define_fs_use(SECURITY_FS_USE_XATTR)) return -1;}
                        | FSUSETASK identifier security_context_def ';'
                        {if (define_fs_use(SECURITY_FS_USE_TASK)) return -1;}
                        | FSUSETRANS identifier security_context_def ';'
                        {if (define_fs_use(SECURITY_FS_USE_TRANS)) return -1;}
                        ;
opt_genfs_contexts      : genfs_contexts
                        |
                        ;
genfs_contexts          : genfs_context_def
                        | genfs_contexts genfs_context_def
                        ;
genfs_context_def	: GENFSCON identifier path '-' identifier security_context_def
			{if (define_genfs_context(1)) return -1;}
			| GENFSCON identifier path '-' '-' {insert_id("-", 0);} security_context_def
			{if (define_genfs_context(1)) return -1;}
                        | GENFSCON identifier path security_context_def
			{if (define_genfs_context(0)) return -1;}
			;
ipv4_addr_def		: IPV4_ADDR
			{ if (insert_id(yytext,0)) return -1; }
			;
security_context_def	: identifier ':' identifier ':' identifier opt_mls_range_def
	                ;
opt_mls_range_def	: ':' mls_range_def
			|	
			;
mls_range_def		: mls_level_def '-' mls_level_def
			{if (insert_separator(0)) return -1;}
	                | mls_level_def
			{if (insert_separator(0)) return -1;}
	                ;
mls_level_def		: identifier ':' id_comma_list
			{if (insert_separator(0)) return -1;}
	                | identifier
			{if (insert_separator(0)) return -1;}
	                ;
id_comma_list           : identifier
			| id_comma_list ',' identifier
			;
tilde			: '~'
			;
asterisk		: '*'
			;
names           	: identifier
			{ if (insert_separator(0)) return -1; }
			| nested_id_set
			{ if (insert_separator(0)) return -1; }
			| asterisk
                        { if (insert_id("*", 0)) return -1; 
			  if (insert_separator(0)) return -1; }
			| tilde identifier
                        { if (insert_id("~", 0)) return -1;
			  if (insert_separator(0)) return -1; }
			| tilde nested_id_set
	 		{ if (insert_id("~", 0)) return -1; 
			  if (insert_separator(0)) return -1; }
                        | identifier '-' { if (insert_id("-", 0)) return -1; } identifier 
			{ if (insert_separator(0)) return -1; }
			;
tilde_push              : tilde
                        { if (insert_id("~", 1)) return -1; }
			;
asterisk_push           : asterisk
                        { if (insert_id("*", 1)) return -1; }
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
			{ if (insert_id(yytext, 1)) return -1; }
			;
identifier_list		: identifier
			| identifier_list identifier
			;
nested_id_set           : '{' nested_id_list '}'
                        ;
nested_id_list          : nested_id_element | nested_id_list nested_id_element
                        ;
nested_id_element       : identifier | '-' { if (insert_id("-", 0)) return -1; } identifier | nested_id_set
                        ;
identifier		: IDENTIFIER
			{ if (insert_id(yytext,0)) return -1; }
			;
path     		: PATH
			{ if (insert_id(yytext,0)) return -1; }
			;
number			: NUMBER 
			{ $$ = strtoul(yytext,NULL,0); }
			;
ipv6_addr		: IPV6_ADDR
			{ if (insert_id(yytext,0)) return -1; }
			;

/*********** module grammar below ***********/

module_policy           : module_def avrules_block
                        { if (end_avrule_block(pass) == -1) return -1;
                          if (policydb_index_others(NULL, policydbp, 0)) return -1;
                        }
                        ;
module_def              : MODULE identifier version_identifier ';'
                        { if (define_policy(pass, 1) == -1) return -1; }
                        ;
version_identifier      : VERSION_IDENTIFIER
                        { if (insert_id(yytext,0)) return -1; }
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
                        { if (require_class(pass)) return -1; }
                        ;
require_decl_def        : ROLE        { $$ = require_role; }
                        | TYPE        { $$ = require_type; }
                        | ATTRIBUTE   { $$ = require_attribute; }
                        | USER        { $$ = require_user; }
                        | BOOL        { $$ = require_bool; }
                        | SENSITIVITY { $$ = require_sens; }
                        | CATEGORY    { $$ = require_cat; }
                        ;
require_id_list         : identifier
                        { if ($<require_func>0 (pass)) return -1; }
                        | require_id_list ',' identifier
                        { if ($<require_func>0 (pass)) return -1; }
                        ;
optional_block          : optional_decl '{' avrules_block '}'
                        { if (end_avrule_block(pass) == -1) return -1; }
                          optional_else
                        { if (end_optional(pass) == -1) return -1; }
                        ;
optional_else           : else_decl '{' avrules_block '}'
                        { if (end_avrule_block(pass) == -1) return -1; }
                        | /* empty */
                        ;
optional_decl           : OPTIONAL
                        { if (begin_optional(pass) == -1) return -1; }
                        ;
else_decl               : ELSE
                        { if (begin_optional_else(pass) == -1) return -1; }
                        ;
avrule_user_defs        : user_def avrule_user_defs
                        | /* empty */
                        ;
%%

/* initialize all of the state variables for the scanner/parser */
void init_parser(int pass_number)
{
	policydb_lineno = 1;
	source_lineno = 1;
	policydb_errors = 0;
	pass = pass_number;
}

void yyerror2(char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(errormsg, ERRORMSG_LEN, fmt, ap);
	yyerror(errormsg);
	va_end(ap);
}

#define DEBUG 1

static int insert_separator(int push)
{
	int error;

	if (push)
		error = queue_push(id_queue, 0);
	else
		error = queue_insert(id_queue, 0);

	if (error) {
		yyerror("queue overflow");
		return -1;
	}
	return 0;
}

static int insert_id(char *id, int push)
{
	char *newid = 0;
	int error;

	newid = (char *)malloc(strlen(id) + 1);
	if (!newid) {
		yyerror("out of memory");
		return -1;
	}
	strcpy(newid, id);
	if (push)
		error = queue_push(id_queue, (queue_element_t) newid);
	else
		error = queue_insert(id_queue, (queue_element_t) newid);

	if (error) {
		yyerror("queue overflow");
		free(newid);
		return -1;
	}
	return 0;
}

/* If the identifier has a dot within it and that its first character
   is not a dot then return 1, else return 0. */
static int id_has_dot(char *id)
{
	if (strchr(id, '.') >= id + 1) {
		return 1;
	}
	return 0;
}

static int define_class(void)
{
	char *id = 0;
	class_datum_t *datum = 0;
	int ret;
	uint32_t value;

	if (pass == 2) {
		id = queue_remove(id_queue);
		free(id);
		return 0;
	}

	id = (char *)queue_remove(id_queue);
	if (!id) {
		yyerror("no class name for class definition?");
		return -1;
	}
	datum = (class_datum_t *) malloc(sizeof(class_datum_t));
	if (!datum) {
		yyerror("out of memory");
		goto bad;
	}
	memset(datum, 0, sizeof(class_datum_t));
	ret = declare_symbol(SYM_CLASSES, id, datum, &value, &value);
	switch (ret) {
	case -3:{
			yyerror("Out of memory!");
			goto bad;
		}
	case -2:{
			yyerror2("duplicate declaration of class %s", id);
			goto bad;
		}
	case -1:{
			yyerror("could not declare class here");
			goto bad;
		}
	case 0:
	case 1:{
			break;
		}
	default:{
			assert(0);	/* should never get here */
		}
	}
	datum->s.value = value;
	return 0;

      bad:
	if (id)
		free(id);
	if (datum)
		free(datum);
	return -1;
}

static int define_initial_sid(void)
{
	char *id = 0;
	ocontext_t *newc = 0, *c, *head;

	if (pass == 2) {
		id = queue_remove(id_queue);
		free(id);
		return 0;
	}

	id = (char *)queue_remove(id_queue);
	if (!id) {
		yyerror("no sid name for SID definition?");
		return -1;
	}
	newc = (ocontext_t *) malloc(sizeof(ocontext_t));
	if (!newc) {
		yyerror("out of memory");
		goto bad;
	}
	memset(newc, 0, sizeof(ocontext_t));
	newc->u.name = id;
	context_init(&newc->context[0]);
	head = policydbp->ocontexts[OCON_ISID];

	for (c = head; c; c = c->next) {
		if (!strcmp(newc->u.name, c->u.name)) {
			sprintf(errormsg, "duplicate initial SID %s", id);
			yyerror(errormsg);
			goto bad;
		}
	}

	if (head) {
		newc->sid[0] = head->sid[0] + 1;
	} else {
		newc->sid[0] = 1;
	}
	newc->next = head;
	policydbp->ocontexts[OCON_ISID] = newc;

	return 0;

      bad:
	if (id)
		free(id);
	if (newc)
		free(newc);
	return -1;
}

static int define_common_perms(void)
{
	char *id = 0, *perm = 0;
	common_datum_t *comdatum = 0;
	perm_datum_t *perdatum = 0;
	int ret;

	if (pass == 2) {
		while ((id = queue_remove(id_queue)))
			free(id);
		return 0;
	}

	id = (char *)queue_remove(id_queue);
	if (!id) {
		yyerror("no common name for common perm definition?");
		return -1;
	}
	comdatum = hashtab_search(policydbp->p_commons.table, id);
	if (comdatum) {
		snprintf(errormsg, ERRORMSG_LEN,
			 "duplicate declaration for common %s\n", id);
		yyerror(errormsg);
		return -1;
	}
	comdatum = (common_datum_t *) malloc(sizeof(common_datum_t));
	if (!comdatum) {
		yyerror("out of memory");
		goto bad;
	}
	memset(comdatum, 0, sizeof(common_datum_t));
	ret = hashtab_insert(policydbp->p_commons.table,
			     (hashtab_key_t) id, (hashtab_datum_t) comdatum);

	if (ret == HASHTAB_PRESENT) {
		yyerror("duplicate common definition");
		goto bad;
	}
	if (ret == HASHTAB_OVERFLOW) {
		yyerror("hash table overflow");
		goto bad;
	}
	comdatum->s.value = policydbp->p_commons.nprim + 1;
	if (symtab_init(&comdatum->permissions, PERM_SYMTAB_SIZE)) {
		yyerror("out of memory");
		goto bad;
	}
	policydbp->p_commons.nprim++;
	while ((perm = queue_remove(id_queue))) {
		perdatum = (perm_datum_t *) malloc(sizeof(perm_datum_t));
		if (!perdatum) {
			yyerror("out of memory");
			goto bad_perm;
		}
		memset(perdatum, 0, sizeof(perm_datum_t));
		perdatum->s.value = comdatum->permissions.nprim + 1;

		if (perdatum->s.value > (sizeof(sepol_access_vector_t) * 8)) {
			yyerror
			    ("too many permissions to fit in an access vector");
			goto bad_perm;
		}
		ret = hashtab_insert(comdatum->permissions.table,
				     (hashtab_key_t) perm,
				     (hashtab_datum_t) perdatum);

		if (ret == HASHTAB_PRESENT) {
			sprintf(errormsg,
				"duplicate permission %s in common %s", perm,
				id);
			yyerror(errormsg);
			goto bad_perm;
		}
		if (ret == HASHTAB_OVERFLOW) {
			yyerror("hash table overflow");
			goto bad_perm;
		}
		comdatum->permissions.nprim++;
	}

	return 0;

      bad:
	if (id)
		free(id);
	if (comdatum)
		free(comdatum);
	return -1;

      bad_perm:
	if (perm)
		free(perm);
	if (perdatum)
		free(perdatum);
	return -1;
}

static int define_av_perms(int inherits)
{
	char *id;
	class_datum_t *cladatum;
	common_datum_t *comdatum;
	perm_datum_t *perdatum = 0, *perdatum2 = 0;
	int ret;

	if (pass == 2) {
		while ((id = queue_remove(id_queue)))
			free(id);
		return 0;
	}

	id = (char *)queue_remove(id_queue);
	if (!id) {
		yyerror("no tclass name for av perm definition?");
		return -1;
	}
	cladatum = (class_datum_t *) hashtab_search(policydbp->p_classes.table,
						    (hashtab_key_t) id);
	if (!cladatum) {
		sprintf(errormsg, "class %s is not defined", id);
		yyerror(errormsg);
		goto bad;
	}
	free(id);

	if (cladatum->comdatum || cladatum->permissions.nprim) {
		yyerror("duplicate access vector definition");
		return -1;
	}
	if (symtab_init(&cladatum->permissions, PERM_SYMTAB_SIZE)) {
		yyerror("out of memory");
		return -1;
	}
	if (inherits) {
		id = (char *)queue_remove(id_queue);
		if (!id) {
			yyerror
			    ("no inherits name for access vector definition?");
			return -1;
		}
		comdatum =
		    (common_datum_t *) hashtab_search(policydbp->p_commons.
						      table,
						      (hashtab_key_t) id);

		if (!comdatum) {
			sprintf(errormsg, "common %s is not defined", id);
			yyerror(errormsg);
			goto bad;
		}
		cladatum->comkey = id;
		cladatum->comdatum = comdatum;

		/*
		 * Class-specific permissions start with values 
		 * after the last common permission.
		 */
		cladatum->permissions.nprim += comdatum->permissions.nprim;
	}
	while ((id = queue_remove(id_queue))) {
		perdatum = (perm_datum_t *) malloc(sizeof(perm_datum_t));
		if (!perdatum) {
			yyerror("out of memory");
			goto bad;
		}
		memset(perdatum, 0, sizeof(perm_datum_t));
		perdatum->s.value = ++cladatum->permissions.nprim;

		if (perdatum->s.value > (sizeof(sepol_access_vector_t) * 8)) {
			yyerror
			    ("too many permissions to fit in an access vector");
			goto bad;
		}
		if (inherits) {
			/*
			 * Class-specific permissions and 
			 * common permissions exist in the same
			 * name space.
			 */
			perdatum2 =
			    (perm_datum_t *) hashtab_search(cladatum->comdatum->
							    permissions.table,
							    (hashtab_key_t) id);
			if (perdatum2) {
				sprintf(errormsg,
					"permission %s conflicts with an inherited permission",
					id);
				yyerror(errormsg);
				goto bad;
			}
		}
		ret = hashtab_insert(cladatum->permissions.table,
				     (hashtab_key_t) id,
				     (hashtab_datum_t) perdatum);

		if (ret == HASHTAB_PRESENT) {
			sprintf(errormsg, "duplicate permission %s", id);
			yyerror(errormsg);
			goto bad;
		}
		if (ret == HASHTAB_OVERFLOW) {
			yyerror("hash table overflow");
			goto bad;
		}
		if (add_perm_to_class(perdatum->s.value, cladatum->s.value)) {
			yyerror("out of memory");
			goto bad;
		}
	}

	return 0;

      bad:
	if (id)
		free(id);
	if (perdatum)
		free(perdatum);
	return -1;
}

static int define_sens(void)
{
	char *id;
	mls_level_t *level = 0;
	level_datum_t *datum = 0, *aliasdatum = 0;
	int ret;
	uint32_t value;		/* dummy variable -- its value is never used */

	if (!mlspol) {
		yyerror("sensitivity definition in non-MLS configuration");
		return -1;
	}

	if (pass == 2) {
		while ((id = queue_remove(id_queue)))
			free(id);
		return 0;
	}

	id = (char *)queue_remove(id_queue);
	if (!id) {
		yyerror("no sensitivity name for sensitivity definition?");
		return -1;
	}
	if (id_has_dot(id)) {
		yyerror("sensitivity identifiers may not contain periods");
		goto bad;
	}
	level = (mls_level_t *) malloc(sizeof(mls_level_t));
	if (!level) {
		yyerror("out of memory");
		goto bad;
	}
	mls_level_init(level);
	level->sens = 0;	/* actual value set in define_dominance */
	ebitmap_init(&level->cat);	/* actual value set in define_level */

	datum = (level_datum_t *) malloc(sizeof(level_datum_t));
	if (!datum) {
		yyerror("out of memory");
		goto bad;
	}
	level_datum_init(datum);
	datum->isalias = FALSE;
	datum->level = level;

	ret = declare_symbol(SYM_LEVELS, id, datum, &value, &value);
	switch (ret) {
	case -3:{
			yyerror("Out of memory!");
			goto bad;
		}
	case -2:{
			yyerror("duplicate declaration of sensitivity level");
			goto bad;
		}
	case -1:{
			yyerror("could not declare sensitivity level here");
			goto bad;
		}
	case 0:
	case 1:{
			break;
		}
	default:{
			assert(0);	/* should never get here */
		}
	}

	while ((id = queue_remove(id_queue))) {
		if (id_has_dot(id)) {
			yyerror("sensitivity aliases may not contain periods");
			goto bad_alias;
		}
		aliasdatum = (level_datum_t *) malloc(sizeof(level_datum_t));
		if (!aliasdatum) {
			yyerror("out of memory");
			goto bad_alias;
		}
		level_datum_init(aliasdatum);
		aliasdatum->isalias = TRUE;
		aliasdatum->level = level;

		ret = declare_symbol(SYM_LEVELS, id, aliasdatum, NULL, &value);
		switch (ret) {
		case -3:{
				yyerror("Out of memory!");
				goto bad_alias;
			}
		case -2:{
				yyerror
				    ("duplicate declaration of sensitivity alias");
				goto bad_alias;
			}
		case -1:{
				yyerror
				    ("could not declare sensitivity alias here");
				goto bad_alias;
			}
		case 0:
		case 1:{
				break;
			}
		default:{
				assert(0);	/* should never get here */
			}
		}
	}

	return 0;

      bad:
	if (id)
		free(id);
	if (level)
		free(level);
	if (datum) {
		level_datum_destroy(datum);
		free(datum);
	}
	return -1;

      bad_alias:
	if (id)
		free(id);
	if (aliasdatum) {
		level_datum_destroy(aliasdatum);
		free(aliasdatum);
	}
	return -1;
}

static int define_dominance(void)
{
	level_datum_t *datum;
	int order;
	char *id;

	if (!mlspol) {
		yyerror("dominance definition in non-MLS configuration");
		return -1;
	}

	if (pass == 2) {
		while ((id = queue_remove(id_queue)))
			free(id);
		return 0;
	}

	order = 0;
	while ((id = (char *)queue_remove(id_queue))) {
		datum =
		    (level_datum_t *) hashtab_search(policydbp->p_levels.table,
						     (hashtab_key_t) id);
		if (!datum) {
			sprintf(errormsg,
				"unknown sensitivity %s used in dominance definition",
				id);
			yyerror(errormsg);
			free(id);
			return -1;
		}
		if (datum->level->sens != 0) {
			sprintf(errormsg,
				"sensitivity %s occurs multiply in dominance definition",
				id);
			yyerror(errormsg);
			free(id);
			return -1;
		}
		datum->level->sens = ++order;

		/* no need to keep sensitivity name */
		free(id);
	}

	if (order != policydbp->p_levels.nprim) {
		yyerror
		    ("all sensitivities must be specified in dominance definition");
		return -1;
	}
	return 0;
}

static int define_category(void)
{
	char *id;
	cat_datum_t *datum = 0, *aliasdatum = 0;
	int ret;
	uint32_t value;

	if (!mlspol) {
		yyerror("category definition in non-MLS configuration");
		return -1;
	}

	if (pass == 2) {
		while ((id = queue_remove(id_queue)))
			free(id);
		return 0;
	}

	id = (char *)queue_remove(id_queue);
	if (!id) {
		yyerror("no category name for category definition?");
		return -1;
	}
	if (id_has_dot(id)) {
		yyerror("category identifiers may not contain periods");
		goto bad;
	}
	datum = (cat_datum_t *) malloc(sizeof(cat_datum_t));
	if (!datum) {
		yyerror("out of memory");
		goto bad;
	}
	cat_datum_init(datum);
	datum->isalias = FALSE;

	ret = declare_symbol(SYM_CATS, id, datum, &value, &value);
	switch (ret) {
	case -3:{
			yyerror("Out of memory!");
			goto bad;
		}
	case -2:{
			yyerror("duplicate declaration of category");
			goto bad;
		}
	case -1:{
			yyerror("could not declare category here");
			goto bad;
		}
	case 0:
	case 1:{
			break;
		}
	default:{
			assert(0);	/* should never get here */
		}
	}
	datum->s.value = value;

	while ((id = queue_remove(id_queue))) {
		if (id_has_dot(id)) {
			yyerror("category aliases may not contain periods");
			goto bad_alias;
		}
		aliasdatum = (cat_datum_t *) malloc(sizeof(cat_datum_t));
		if (!aliasdatum) {
			yyerror("out of memory");
			goto bad_alias;
		}
		cat_datum_init(aliasdatum);
		aliasdatum->isalias = TRUE;
		aliasdatum->s.value = datum->s.value;

		ret =
		    declare_symbol(SYM_CATS, id, aliasdatum, NULL,
				   &datum->s.value);
		switch (ret) {
		case -3:{
				yyerror("Out of memory!");
				goto bad_alias;
			}
		case -2:{
				yyerror
				    ("duplicate declaration of category aliases");
				goto bad_alias;
			}
		case -1:{
				yyerror
				    ("could not declare category aliases here");
				goto bad_alias;
			}
		case 0:
		case 1:{
				break;
			}
		default:{
				assert(0);	/* should never get here */
			}
		}
	}

	return 0;

      bad:
	if (id)
		free(id);
	if (datum) {
		cat_datum_destroy(datum);
		free(datum);
	}
	return -1;

      bad_alias:
	if (id)
		free(id);
	if (aliasdatum) {
		cat_datum_destroy(aliasdatum);
		free(aliasdatum);
	}
	return -1;
}

static int clone_level(hashtab_key_t key, hashtab_datum_t datum, void *arg)
{
	level_datum_t *levdatum = (level_datum_t *) datum;
	mls_level_t *level = (mls_level_t *) arg, *newlevel;

	if (levdatum->level == level) {
		levdatum->defined = 1;
		if (!levdatum->isalias)
			return 0;
		newlevel = (mls_level_t *) malloc(sizeof(mls_level_t));
		if (!newlevel)
			return -1;
		if (mls_level_cpy(newlevel, level)) {
			free(newlevel);
			return -1;
		}
		levdatum->level = newlevel;
	}
	return 0;
}

static int define_level(void)
{
	char *id;
	level_datum_t *levdatum;

	if (!mlspol) {
		yyerror("level definition in non-MLS configuration");
		return -1;
	}

	if (pass == 2) {
		while ((id = queue_remove(id_queue)))
			free(id);
		return 0;
	}

	id = (char *)queue_remove(id_queue);
	if (!id) {
		yyerror("no level name for level definition?");
		return -1;
	}
	levdatum = (level_datum_t *) hashtab_search(policydbp->p_levels.table,
						    (hashtab_key_t) id);
	if (!levdatum) {
		sprintf(errormsg,
			"unknown sensitivity %s used in level definition", id);
		yyerror(errormsg);
		free(id);
		return -1;
	}
	if (ebitmap_length(&levdatum->level->cat)) {
		sprintf(errormsg,
			"sensitivity %s used in multiple level definitions",
			id);
		yyerror(errormsg);
		free(id);
		return -1;
	}
	free(id);

	levdatum->defined = 1;

	while ((id = queue_remove(id_queue))) {
		cat_datum_t *cdatum;
		int range_start, range_end, i;

		if (id_has_dot(id)) {
			char *id_start = id;
			char *id_end = strchr(id, '.');

			*(id_end++) = '\0';

			cdatum =
			    (cat_datum_t *) hashtab_search(policydbp->p_cats.
							   table,
							   (hashtab_key_t)
							   id_start);
			if (!cdatum) {
				sprintf(errormsg, "unknown category %s",
					id_start);
				yyerror(errormsg);
				free(id);
				return -1;
			}
			range_start = cdatum->s.value - 1;
			cdatum =
			    (cat_datum_t *) hashtab_search(policydbp->p_cats.
							   table,
							   (hashtab_key_t)
							   id_end);
			if (!cdatum) {
				sprintf(errormsg, "unknown category %s",
					id_end);
				yyerror(errormsg);
				free(id);
				return -1;
			}
			range_end = cdatum->s.value - 1;

			if (range_end < range_start) {
				sprintf(errormsg, "category range is invalid");
				yyerror(errormsg);
				free(id);
				return -1;
			}
		} else {
			cdatum =
			    (cat_datum_t *) hashtab_search(policydbp->p_cats.
							   table,
							   (hashtab_key_t) id);
			range_start = range_end = cdatum->s.value - 1;
		}

		for (i = range_start; i <= range_end; i++) {
			if (ebitmap_set_bit(&levdatum->level->cat, i, TRUE)) {
				yyerror("out of memory");
				free(id);
				return -1;
			}
		}

		free(id);
	}

	if (hashtab_map
	    (policydbp->p_levels.table, clone_level, levdatum->level)) {
		yyerror("out of memory");
		return -1;
	}

	return 0;
}

static int define_attrib(void)
{
	if (pass == 2) {
		free(queue_remove(id_queue));
		return 0;
	}

	if (declare_type(TRUE, TRUE) == NULL) {
		return -1;
	}
	return 0;
}

static int add_aliases_to_type(type_datum_t * type)
{
	char *id;
	type_datum_t *aliasdatum = NULL;
	int ret;
	while ((id = queue_remove(id_queue))) {
		if (id_has_dot(id)) {
			free(id);
			yyerror
			    ("type alias identifiers may not contain periods");
			return -1;
		}
		aliasdatum = (type_datum_t *) malloc(sizeof(type_datum_t));
		if (!aliasdatum) {
			free(id);
			yyerror("Out of memory!");
			return -1;
		}
		memset(aliasdatum, 0, sizeof(type_datum_t));
		aliasdatum->s.value = type->s.value;

		ret = declare_symbol(SYM_TYPES, id, aliasdatum,
				     NULL, &aliasdatum->s.value);
		switch (ret) {
		case -3:{
				yyerror("Out of memory!");
				goto cleanup;
			}
		case -2:{
				yyerror2("duplicate declaration of alias %s",
					 id);
				goto cleanup;
			}
		case -1:{
				yyerror("could not declare alias here");
				goto cleanup;
			}
		case 0:
		case 1:{
				break;
			}
		default:{
				assert(0);	/* should never get here */
			}
		}
	}
	return 0;
      cleanup:
	free(id);
	type_datum_destroy(aliasdatum);
	free(aliasdatum);
	return -1;
}

static int define_typealias(void)
{
	char *id;
	type_datum_t *t;

	if (pass == 2) {
		while ((id = queue_remove(id_queue)))
			free(id);
		return 0;
	}

	id = (char *)queue_remove(id_queue);
	if (!id) {
		yyerror("no type name for typealias definition?");
		return -1;
	}

	if (!is_id_in_scope(SYM_TYPES, id)) {
		yyerror2("type %s is not within scope", id);
		free(id);
		return -1;
	}
	t = hashtab_search(policydbp->p_types.table, id);
	if (!t || t->flavor == TYPE_ATTRIB) {
		sprintf(errormsg,
			"unknown type %s, or it was already declared as an attribute",
			id);
		yyerror(errormsg);
		free(id);
		return -1;
	}
	return add_aliases_to_type(t);
}

static int define_typeattribute(void)
{
	char *id;
	type_datum_t *t, *attr;

	if (pass == 2) {
		while ((id = queue_remove(id_queue)))
			free(id);
		return 0;
	}

	id = (char *)queue_remove(id_queue);
	if (!id) {
		yyerror("no type name for typeattribute definition?");
		return -1;
	}

	if (!is_id_in_scope(SYM_TYPES, id)) {
		yyerror2("type %s is not within scope", id);
		free(id);
		return -1;
	}
	t = hashtab_search(policydbp->p_types.table, id);
	if (!t || t->flavor == TYPE_ATTRIB) {
		sprintf(errormsg, "unknown type %s", id);
		yyerror(errormsg);
		free(id);
		return -1;
	}

	while ((id = queue_remove(id_queue))) {
		if (!is_id_in_scope(SYM_TYPES, id)) {
			yyerror2("attribute %s is not within scope", id);
			free(id);
			return -1;
		}
		attr = hashtab_search(policydbp->p_types.table, id);
		if (!attr) {
			sprintf(errormsg, "attribute %s is not declared", id);
			/* treat it as a fatal error */
			yyerror(errormsg);
			free(id);
			return -1;
		}

		if (attr->flavor != TYPE_ATTRIB) {
			sprintf(errormsg, "%s is a type, not an attribute", id);
			yyerror(errormsg);
			free(id);
			return -1;
		}

		if ((attr = get_local_type(id, attr->s.value, 1)) == NULL) {
			yyerror("Out of memory!");
			return -1;
		}

		if (ebitmap_set_bit(&attr->types, (t->s.value - 1), TRUE)) {
			yyerror("out of memory");
			return -1;
		}
	}

	return 0;
}

static int define_type(int alias)
{
	char *id;
	type_datum_t *datum, *attr;
	int newattr = 0;

	if (pass == 2) {
		while ((id = queue_remove(id_queue)))
			free(id);
		if (alias) {
			while ((id = queue_remove(id_queue)))
				free(id);
		}
		return 0;
	}

	if ((datum = declare_type(TRUE, FALSE)) == NULL) {
		return -1;
	}

	if (alias) {
		if (add_aliases_to_type(datum) == -1) {
			return -1;
		}
	}

	while ((id = queue_remove(id_queue))) {
		if (!is_id_in_scope(SYM_TYPES, id)) {
			yyerror2("attribute %s is not within scope", id);
			free(id);
			return -1;
		}
		attr = hashtab_search(policydbp->p_types.table, id);
		if (!attr) {
			sprintf(errormsg, "attribute %s is not declared", id);

			/* treat it as a fatal error */
			yyerror(errormsg);
			return -1;
		} else {
			newattr = 0;
		}

		if (attr->flavor != TYPE_ATTRIB) {
			sprintf(errormsg, "%s is a type, not an attribute", id);
			yyerror(errormsg);
			return -1;
		}

		if ((attr = get_local_type(id, attr->s.value, 1)) == NULL) {
			yyerror("Out of memory!");
			return -1;
		}

		if (ebitmap_set_bit(&attr->types, datum->s.value - 1, TRUE)) {
			yyerror("Out of memory");
			return -1;
		}
	}

	return 0;
}

struct val_to_name {
	unsigned int val;
	char *name;
};

/* Adds a type, given by its textual name, to a typeset.  If *add is
   0, then add the type to the negative set; otherwise if *add is 1
   then add it to the positive side. */
static int set_types(type_set_t * set, char *id, int *add, char starallowed)
{
	type_datum_t *t;

	if (strcmp(id, "*") == 0) {
		if (!starallowed) {
			yyerror("* not allowed in this type of rule");
			return -1;
		}
		/* set TYPE_STAR flag */
		set->flags = TYPE_STAR;
		free(id);
		*add = 1;
		return 0;
	}

	if (strcmp(id, "~") == 0) {
		if (!starallowed) {
			yyerror("~ not allowed in this type of rule");
			return -1;
		}
		/* complement the set */
		set->flags = TYPE_COMP;
		free(id);
		*add = 1;
		return 0;
	}

	if (strcmp(id, "-") == 0) {
		*add = 0;
		free(id);
		return 0;
	}

	if (!is_id_in_scope(SYM_TYPES, id)) {
		yyerror2("type %s is not within scope", id);
		free(id);
		return -1;
	}
	t = hashtab_search(policydbp->p_types.table, id);
	if (!t) {
		snprintf(errormsg, ERRORMSG_LEN, "unknown type %s", id);
		yyerror(errormsg);
		free(id);
		return -1;
	}

	if (*add == 0) {
		if (ebitmap_set_bit(&set->negset, t->s.value - 1, TRUE))
			goto oom;
	} else {
		if (ebitmap_set_bit(&set->types, t->s.value - 1, TRUE))
			goto oom;
	}
	free(id);
	*add = 1;
	return 0;
      oom:
	yyerror("Out of memory");
	free(id);
	return -1;
}

static int define_compute_type_helper(int which, avrule_t ** rule)
{
	char *id;
	type_datum_t *datum;
	class_datum_t *cladatum;
	ebitmap_t tclasses;
	ebitmap_node_t *node;
	avrule_t *avrule;
	class_perm_node_t *perm;
	int i, add = 1;

	avrule = malloc(sizeof(avrule_t));
	if (!avrule) {
		yyerror("out of memory");
		return -1;
	}
	avrule_init(avrule);
	avrule->specified = which;
	avrule->line = policydb_lineno;

	while ((id = queue_remove(id_queue))) {
		if (set_types(&avrule->stypes, id, &add, 0))
			return -1;
	}
	add = 1;
	while ((id = queue_remove(id_queue))) {
		if (set_types(&avrule->ttypes, id, &add, 0))
			return -1;
	}

	ebitmap_init(&tclasses);
	while ((id = queue_remove(id_queue))) {
		if (!is_id_in_scope(SYM_CLASSES, id)) {
			yyerror2("class %s is not within scope", id);
			free(id);
			goto bad;
		}
		cladatum = hashtab_search(policydbp->p_classes.table, id);
		if (!cladatum) {
			sprintf(errormsg, "unknown class %s", id);
			yyerror(errormsg);
			goto bad;
		}
		if (ebitmap_set_bit(&tclasses, cladatum->s.value - 1, TRUE)) {
			yyerror("Out of memory");
			goto bad;
		}
		free(id);
	}

	id = (char *)queue_remove(id_queue);
	if (!id) {
		yyerror("no newtype?");
		goto bad;
	}
	if (!is_id_in_scope(SYM_TYPES, id)) {
		yyerror2("type %s is not within scope", id);
		free(id);
		goto bad;
	}
	datum = (type_datum_t *) hashtab_search(policydbp->p_types.table,
						(hashtab_key_t) id);
	if (!datum || datum->flavor == TYPE_ATTRIB) {
		sprintf(errormsg, "unknown type %s", id);
		yyerror(errormsg);
		goto bad;
	}

	ebitmap_for_each_bit(&tclasses, node, i) {
		if (ebitmap_node_get_bit(node, i)) {
			perm = malloc(sizeof(class_perm_node_t));
			if (!perm) {
				yyerror("out of memory");
				return -1;
			}
			class_perm_node_init(perm);
			perm->class = i + 1;
			perm->data = datum->s.value;
			perm->next = avrule->perms;
			avrule->perms = perm;
		}
	}
	ebitmap_destroy(&tclasses);

	*rule = avrule;
	return 0;

      bad:
	avrule_destroy(avrule);
	free(avrule);
	return -1;
}

static int define_compute_type(int which)
{
	char *id;
	avrule_t *avrule;

	if (pass == 1) {
		while ((id = queue_remove(id_queue)))
			free(id);
		while ((id = queue_remove(id_queue)))
			free(id);
		while ((id = queue_remove(id_queue)))
			free(id);
		id = queue_remove(id_queue);
		free(id);
		return 0;
	}

	if (define_compute_type_helper(which, &avrule))
		return -1;

	append_avrule(avrule);
	return 0;
}

static avrule_t *define_cond_compute_type(int which)
{
	char *id;
	avrule_t *avrule;

	if (pass == 1) {
		while ((id = queue_remove(id_queue)))
			free(id);
		while ((id = queue_remove(id_queue)))
			free(id);
		while ((id = queue_remove(id_queue)))
			free(id);
		id = queue_remove(id_queue);
		free(id);
		return (avrule_t *) 1;
	}

	if (define_compute_type_helper(which, &avrule))
		return COND_ERR;

	return avrule;
}

static int define_bool(void)
{
	char *id, *bool_value;
	cond_bool_datum_t *datum;
	int ret;
	uint32_t value;

	if (pass == 2) {
		while ((id = queue_remove(id_queue)))
			free(id);
		return 0;
	}

	id = (char *)queue_remove(id_queue);
	if (!id) {
		yyerror("no identifier for bool definition?");
		return -1;
	}
	if (id_has_dot(id)) {
		free(id);
		yyerror("boolean identifiers may not contain periods");
		return -1;
	}
	datum = (cond_bool_datum_t *) malloc(sizeof(cond_bool_datum_t));
	if (!datum) {
		yyerror("out of memory");
		free(id);
		return -1;
	}
	memset(datum, 0, sizeof(cond_bool_datum_t));
	ret = declare_symbol(SYM_BOOLS, id, datum, &value, &value);
	switch (ret) {
	case -3:{
			yyerror("Out of memory!");
			goto cleanup;
		}
	case -2:{
			yyerror2("duplicate declaration of boolean %s", id);
			goto cleanup;
		}
	case -1:{
			yyerror("could not declare boolean here");
			goto cleanup;
		}
	case 0:
	case 1:{
			break;
		}
	default:{
			assert(0);	/* should never get here */
		}
	}
	datum->s.value = value;

	bool_value = (char *)queue_remove(id_queue);
	if (!bool_value) {
		yyerror("no default value for bool definition?");
		free(id);
		return -1;
	}

	datum->state = (int)(bool_value[0] == 'T') ? 1 : 0;
	return 0;
      cleanup:
	cond_destroy_bool(id, datum, NULL);
	return -1;
}

static avrule_t *define_cond_pol_list(avrule_t * avlist, avrule_t * sl)
{
	if (pass == 1) {
		/* return something so we get through pass 1 */
		return (avrule_t *) 1;
	}

	if (sl == NULL) {
		/* This is a require block, return previous list */
		return avlist;
	}

	/* prepend the new avlist to the pre-existing one */
	sl->next = avlist;
	return sl;
}

static int define_te_avtab_helper(int which, avrule_t ** rule)
{
	char *id;
	class_datum_t *cladatum;
	perm_datum_t *perdatum = NULL;
	class_perm_node_t *perms, *tail = NULL, *cur_perms = NULL;
	ebitmap_t tclasses;
	ebitmap_node_t *node;
	avrule_t *avrule;
	unsigned int i;
	int add = 1, ret = 0;
	int suppress = 0;

	avrule = (avrule_t *) malloc(sizeof(avrule_t));
	if (!avrule) {
		yyerror("memory error");
		ret = -1;
		goto out;
	}
	avrule_init(avrule);
	avrule->specified = which;
	avrule->line = policydb_lineno;

	while ((id = queue_remove(id_queue))) {
		if (set_types
		    (&avrule->stypes, id, &add,
		     which == AVRULE_NEVERALLOW ? 1 : 0)) {
			ret = -1;
			goto out;
		}
	}
	add = 1;
	while ((id = queue_remove(id_queue))) {
		if (strcmp(id, "self") == 0) {
			free(id);
			avrule->flags |= RULE_SELF;
			continue;
		}
		if (set_types
		    (&avrule->ttypes, id, &add,
		     which == AVRULE_NEVERALLOW ? 1 : 0)) {
			ret = -1;
			goto out;
		}
	}

	ebitmap_init(&tclasses);
	while ((id = queue_remove(id_queue))) {
		if (!is_id_in_scope(SYM_CLASSES, id)) {
			yyerror2("class %s is not within scope", id);
			ret = -1;
			goto out;
		}
		cladatum = hashtab_search(policydbp->p_classes.table, id);
		if (!cladatum) {
			sprintf(errormsg, "unknown class %s used in rule", id);
			yyerror(errormsg);
			ret = -1;
			goto out;
		}
		if (ebitmap_set_bit(&tclasses, cladatum->s.value - 1, TRUE)) {
			yyerror("Out of memory");
			ret = -1;
			goto out;
		}
		free(id);
	}

	perms = NULL;
	ebitmap_for_each_bit(&tclasses, node, i) {
		if (!ebitmap_node_get_bit(node, i))
			continue;
		cur_perms =
		    (class_perm_node_t *) malloc(sizeof(class_perm_node_t));
		if (!cur_perms) {
			yyerror("out of memory");
			ret = -1;
			goto out;
		}
		class_perm_node_init(cur_perms);
		cur_perms->class = i + 1;
		if (!perms)
			perms = cur_perms;
		if (tail)
			tail->next = cur_perms;
		tail = cur_perms;
	}

	while ((id = queue_remove(id_queue))) {
		cur_perms = perms;
		ebitmap_for_each_bit(&tclasses, node, i) {
			if (!ebitmap_node_get_bit(node, i))
				continue;
			cladatum = policydbp->class_val_to_struct[i];

			if (strcmp(id, "*") == 0) {
				/* set all permissions in the class */
				cur_perms->data = ~0U;
				goto next;
			}

			if (strcmp(id, "~") == 0) {
				/* complement the set */
				if (which == AVRULE_DONTAUDIT)
					yywarn("dontaudit rule with a ~?");
				cur_perms->data = ~cur_perms->data;
				goto next;
			}

			perdatum =
			    hashtab_search(cladatum->permissions.table, id);
			if (!perdatum) {
				if (cladatum->comdatum) {
					perdatum =
					    hashtab_search(cladatum->comdatum->
							   permissions.table,
							   id);
				}
			}
			if (!perdatum) {
				sprintf(errormsg,
					"permission %s is not defined for class %s",
					id, policydbp->p_class_val_to_name[i]);
				if (!suppress)
					yyerror(errormsg);
				continue;
			} else
			    if (!is_perm_in_scope
				(id, policydbp->p_class_val_to_name[i])) {
				if (!suppress) {
					yyerror2
					    ("permission %s of class %s is not within scope",
					     id,
					     policydbp->p_class_val_to_name[i]);
				}
				continue;
			} else {
				cur_perms->data |= 1U << (perdatum->s.value - 1);
			}
		      next:
			cur_perms = cur_perms->next;
		}

		free(id);
	}

	ebitmap_destroy(&tclasses);

	avrule->perms = perms;
	*rule = avrule;

      out:
	return ret;

}

static avrule_t *define_cond_te_avtab(int which)
{
	char *id;
	avrule_t *avrule;
	int i;

	if (pass == 1) {
		for (i = 0; i < 4; i++) {
			while ((id = queue_remove(id_queue)))
				free(id);
		}
		return (avrule_t *) 1;	/* any non-NULL value */
	}

	if (define_te_avtab_helper(which, &avrule))
		return COND_ERR;

	return avrule;
}

static int define_te_avtab(int which)
{
	char *id;
	avrule_t *avrule;
	int i;

	if (pass == 1) {
		for (i = 0; i < 4; i++) {
			while ((id = queue_remove(id_queue)))
				free(id);
		}
		return 0;
	}

	if (define_te_avtab_helper(which, &avrule))
		return -1;

	/* append this avrule to the end of the current rules list */
	append_avrule(avrule);
	return 0;
}

static int define_role_types(void)
{
	role_datum_t *role;
	char *id;
	int add = 1;

	if (pass == 1) {
		while ((id = queue_remove(id_queue)))
			free(id);
		return 0;
	}

	if ((role = declare_role()) == NULL) {
		return -1;
	}
	while ((id = queue_remove(id_queue))) {
		if (set_types(&role->types, id, &add, 0))
			return -1;
	}

	return 0;
}

static role_datum_t *merge_roles_dom(role_datum_t * r1, role_datum_t * r2)
{
	role_datum_t *new;

	if (pass == 1) {
		return (role_datum_t *) 1;	/* any non-NULL value */
	}

	new = malloc(sizeof(role_datum_t));
	if (!new) {
		yyerror("out of memory");
		return NULL;
	}
	memset(new, 0, sizeof(role_datum_t));
	new->s.value = 0;		/* temporary role */
	if (ebitmap_or(&new->dominates, &r1->dominates, &r2->dominates)) {
		yyerror("out of memory");
		return NULL;
	}
	if (ebitmap_or(&new->types.types, &r1->types.types, &r2->types.types)) {
		yyerror("out of memory");
		return NULL;
	}
	if (!r1->s.value) {
		/* free intermediate result */
		type_set_destroy(&r1->types);
		ebitmap_destroy(&r1->dominates);
		free(r1);
	}
	if (!r2->s.value) {
		/* free intermediate result */
		yyerror("right hand role is temporary?");
		type_set_destroy(&r2->types);
		ebitmap_destroy(&r2->dominates);
		free(r2);
	}
	return new;
}

/* This function eliminates the ordering dependency of role dominance rule */
static int dominate_role_recheck(hashtab_key_t key, hashtab_datum_t datum,
				 void *arg)
{
	role_datum_t *rdp = (role_datum_t *) arg;
	role_datum_t *rdatum = (role_datum_t *) datum;
	ebitmap_node_t *node;
	int i;

	/* Don't bother to process against self role */
	if (rdatum->s.value == rdp->s.value)
		return 0;

	/* If a dominating role found */
	if (ebitmap_get_bit(&(rdatum->dominates), rdp->s.value - 1)) {
		ebitmap_t types;
		ebitmap_init(&types);
		if (type_set_expand(&rdp->types, &types, policydbp, 1)) {
			ebitmap_destroy(&types);
			return -1;
		}
		/* raise types and dominates from dominated role */
		ebitmap_for_each_bit(&rdp->dominates, node, i) {
			if (ebitmap_node_get_bit(node, i))
				if (ebitmap_set_bit
				    (&rdatum->dominates, i, TRUE))
					goto oom;
		}
		ebitmap_for_each_bit(&types, node, i) {
			if (ebitmap_node_get_bit(node, i))
				if (ebitmap_set_bit
				    (&rdatum->types.types, i, TRUE))
					goto oom;
		}
		ebitmap_destroy(&types);
	}

	/* go through all the roles */
	return 0;
      oom:
	yyerror("Out of memory");
	return -1;
}

static role_datum_t *define_role_dom(role_datum_t * r)
{
	role_datum_t *role;
	char *role_id;
	ebitmap_node_t *node;
	unsigned int i;
	int ret;

	if (pass == 1) {
		role_id = queue_remove(id_queue);
		free(role_id);
		return (role_datum_t *) 1;	/* any non-NULL value */
	}

	role_id = queue_remove(id_queue);
	if (!is_id_in_scope(SYM_ROLES, role_id)) {
		yyerror2("role %s is not within scope", role_id);
		free(role_id);
		return NULL;
	}
	role = (role_datum_t *) hashtab_search(policydbp->p_roles.table,
					       role_id);
	if (!role) {
		role = (role_datum_t *) malloc(sizeof(role_datum_t));
		if (!role) {
			yyerror("out of memory");
			free(role_id);
			return NULL;
		}
		memset(role, 0, sizeof(role_datum_t));
		ret =
		    declare_symbol(SYM_ROLES, (hashtab_key_t) role_id,
				   (hashtab_datum_t) role, &role->s.value,
				   &role->s.value);
		switch (ret) {
		case -3:{
				yyerror("Out of memory!");
				goto cleanup;
			}
		case -2:{
				yyerror2("duplicate declaration of role %s",
					 role_id);
				goto cleanup;
			}
		case -1:{
				yyerror("could not declare role here");
				goto cleanup;
			}
		case 0:
		case 1:{
				break;
			}
		default:{
				assert(0);	/* should never get here */
			}
		}
		if (ebitmap_set_bit(&role->dominates, role->s.value - 1, TRUE)) {
			yyerror("Out of memory!");
			goto cleanup;
		}
	}
	if (r) {
		ebitmap_t types;
		ebitmap_init(&types);
		ebitmap_for_each_bit(&r->dominates, node, i) {
			if (ebitmap_node_get_bit(node, i))
				if (ebitmap_set_bit(&role->dominates, i, TRUE))
					goto oom;
		}
		if (type_set_expand(&r->types, &types, policydbp, 1)) {
			ebitmap_destroy(&types);
			return NULL;
		}
		ebitmap_for_each_bit(&types, node, i) {
			if (ebitmap_node_get_bit(node, i))
				if (ebitmap_set_bit
				    (&role->types.types, i, TRUE))
					goto oom;
		}
		ebitmap_destroy(&types);
		if (!r->s.value) {
			/* free intermediate result */
			type_set_destroy(&r->types);
			ebitmap_destroy(&r->dominates);
			free(r);
		}
		/*
		 * Now go through all the roles and escalate this role's
		 * dominates and types if a role dominates this role.
		 */
		hashtab_map(policydbp->p_roles.table,
			    dominate_role_recheck, role);
	}
	return role;
      cleanup:
	free(role_id);
	role_datum_destroy(role);
	free(role);
	return NULL;
      oom:
	yyerror("Out of memory");
	goto cleanup;
}

static int role_val_to_name_helper(hashtab_key_t key, hashtab_datum_t datum,
				   void *p)
{
	struct val_to_name *v = p;
	role_datum_t *roldatum;

	roldatum = (role_datum_t *) datum;

	if (v->val == roldatum->s.value) {
		v->name = key;
		return 1;
	}

	return 0;
}

static char *role_val_to_name(unsigned int val)
{
	struct val_to_name v;
	int rc;

	v.val = val;
	rc = hashtab_map(policydbp->p_roles.table, role_val_to_name_helper, &v);
	if (rc)
		return v.name;
	return NULL;
}

static int set_roles(role_set_t * set, char *id)
{
	role_datum_t *r;

	if (strcmp(id, "*") == 0) {
		free(id);
		yyerror("* is not allowed for role sets");
		return -1;
	}

	if (strcmp(id, "~") == 0) {
		free(id);
		yyerror("~ is not allowed for role sets");
		return -1;
	}
	if (!is_id_in_scope(SYM_ROLES, id)) {
		yyerror2("role %s is not within scope", id);
		free(id);
		return -1;
	}
	r = hashtab_search(policydbp->p_roles.table, id);
	if (!r) {
		yyerror2("unknown role %s", id);
		free(id);
		return -1;
	}

	if (ebitmap_set_bit(&set->roles, r->s.value - 1, TRUE)) {
		yyerror("out of memory");
		free(id);
		return -1;
	}
	free(id);
	return 0;
}

static int define_role_trans(void)
{
	char *id;
	role_datum_t *role;
	role_set_t roles;
	type_set_t types;
	ebitmap_t e_types, e_roles;
	ebitmap_node_t *tnode, *rnode;
	struct role_trans *tr = NULL;
	struct role_trans_rule *rule = NULL;
	unsigned int i, j;
	int add = 1;

	if (pass == 1) {
		while ((id = queue_remove(id_queue)))
			free(id);
		while ((id = queue_remove(id_queue)))
			free(id);
		id = queue_remove(id_queue);
		free(id);
		return 0;
	}

	role_set_init(&roles);
	ebitmap_init(&e_roles);
	type_set_init(&types);
	ebitmap_init(&e_types);

	while ((id = queue_remove(id_queue))) {
		if (set_roles(&roles, id))
			return -1;
	}
	add = 1;
	while ((id = queue_remove(id_queue))) {
		if (set_types(&types, id, &add, 0))
			return -1;
	}

	id = (char *)queue_remove(id_queue);
	if (!id) {
		yyerror("no new role in transition definition?");
		goto bad;
	}
	if (!is_id_in_scope(SYM_ROLES, id)) {
		yyerror2("role %s is not within scope", id);
		free(id);
		goto bad;
	}
	role = hashtab_search(policydbp->p_roles.table, id);
	if (!role) {
		sprintf(errormsg,
			"unknown role %s used in transition definition", id);
		yyerror(errormsg);
		goto bad;
	}

	/* This ebitmap business is just to ensure that there are not conflicting role_trans rules */
	if (role_set_expand(&roles, &e_roles, policydbp, NULL))
		goto bad;

	if (type_set_expand(&types, &e_types, policydbp, 1))
		goto bad;

	ebitmap_for_each_bit(&e_roles, rnode, i) {
		if (!ebitmap_node_get_bit(rnode, i))
			continue;
		ebitmap_for_each_bit(&e_types, tnode, j) {
			if (!ebitmap_node_get_bit(tnode, j))
				continue;

			for (tr = policydbp->role_tr; tr; tr = tr->next) {
				if (tr->role == (i + 1) && tr->type == (j + 1)) {
					sprintf(errormsg,
						"duplicate role transition for (%s,%s)",
						role_val_to_name(i + 1),
						policydbp->
						p_type_val_to_name[j]);
					yyerror(errormsg);
					goto bad;
				}
			}

			tr = malloc(sizeof(struct role_trans));
			if (!tr) {
				yyerror("out of memory");
				return -1;
			}
			memset(tr, 0, sizeof(struct role_trans));
			tr->role = i + 1;
			tr->type = j + 1;
			tr->new_role = role->s.value;
			tr->next = policydbp->role_tr;
			policydbp->role_tr = tr;
		}
	}
	/* Now add the real rule */
	rule = malloc(sizeof(struct role_trans_rule));
	if (!rule) {
		yyerror("out of memory");
		return -1;
	}
	memset(rule, 0, sizeof(struct role_trans_rule));
	rule->roles = roles;
	rule->types = types;
	rule->new_role = role->s.value;

	append_role_trans(rule);

	ebitmap_destroy(&e_roles);
	ebitmap_destroy(&e_types);

	return 0;

      bad:
	return -1;
}

static int define_role_allow(void)
{
	char *id;
	struct role_allow_rule *ra = 0;

	if (pass == 1) {
		while ((id = queue_remove(id_queue)))
			free(id);
		while ((id = queue_remove(id_queue)))
			free(id);
		return 0;
	}

	ra = malloc(sizeof(role_allow_rule_t));
	if (!ra) {
		yyerror("out of memory");
		return -1;
	}
	role_allow_rule_init(ra);

	while ((id = queue_remove(id_queue))) {
		if (set_roles(&ra->roles, id))
			return -1;
	}

	while ((id = queue_remove(id_queue))) {
		if (set_roles(&ra->new_roles, id))
			return -1;
	}

	append_role_allow(ra);
	return 0;
}

static constraint_expr_t *constraint_expr_clone(constraint_expr_t * expr)
{
	constraint_expr_t *h = NULL, *l = NULL, *e, *newe;
	for (e = expr; e; e = e->next) {
		newe = malloc(sizeof(*newe));
		if (!newe)
			goto oom;
		if (constraint_expr_init(newe) == -1) {
			free(newe);
			goto oom;
		}
		if (l)
			l->next = newe;
		else
			h = newe;
		l = newe;
		newe->expr_type = e->expr_type;
		newe->attr = e->attr;
		newe->op = e->op;
		if (newe->expr_type == CEXPR_NAMES) {
			if (newe->attr & CEXPR_TYPE) {
				if (type_set_cpy
				    (newe->type_names, e->type_names))
					goto oom;
			} else {
				if (ebitmap_cpy(&newe->names, &e->names))
					goto oom;
			}
		}
	}

	return h;
      oom:
	e = h;
	while (e) {
		l = e;
		e = e->next;
		constraint_expr_destroy(l);
	}
	return NULL;
}

static int define_constraint(constraint_expr_t * expr)
{
	struct constraint_node *node;
	char *id;
	class_datum_t *cladatum;
	perm_datum_t *perdatum;
	ebitmap_t classmap;
	ebitmap_node_t *enode;
	constraint_expr_t *e;
	unsigned int i;
	int depth;
	unsigned char useexpr = 1;

	if (pass == 1) {
		while ((id = queue_remove(id_queue)))
			free(id);
		while ((id = queue_remove(id_queue)))
			free(id);
		return 0;
	}

	depth = -1;
	for (e = expr; e; e = e->next) {
		switch (e->expr_type) {
		case CEXPR_NOT:
			if (depth < 0) {
				yyerror("illegal constraint expression");
				return -1;
			}
			break;
		case CEXPR_AND:
		case CEXPR_OR:
			if (depth < 1) {
				yyerror("illegal constraint expression");
				return -1;
			}
			depth--;
			break;
		case CEXPR_ATTR:
		case CEXPR_NAMES:
			if (e->attr & CEXPR_XTARGET) {
				yyerror("illegal constraint expression");
				return -1;	/* only for validatetrans rules */
			}
			if (depth == (CEXPR_MAXDEPTH - 1)) {
				yyerror("constraint expression is too deep");
				return -1;
			}
			depth++;
			break;
		default:
			yyerror("illegal constraint expression");
			return -1;
		}
	}
	if (depth != 0) {
		yyerror("illegal constraint expression");
		return -1;
	}

	ebitmap_init(&classmap);
	while ((id = queue_remove(id_queue))) {
		if (!is_id_in_scope(SYM_CLASSES, id)) {
			yyerror2("class %s is not within scope", id);
			free(id);
			return -1;
		}
		cladatum =
		    (class_datum_t *) hashtab_search(policydbp->p_classes.table,
						     (hashtab_key_t) id);
		if (!cladatum) {
			sprintf(errormsg, "class %s is not defined", id);
			ebitmap_destroy(&classmap);
			yyerror(errormsg);
			free(id);
			return -1;
		}
		if (ebitmap_set_bit(&classmap, cladatum->s.value - 1, TRUE)) {
			yyerror("out of memory");
			ebitmap_destroy(&classmap);
			free(id);
			return -1;
		}
		node = malloc(sizeof(struct constraint_node));
		if (!node) {
			yyerror("out of memory");
			return -1;
		}
		memset(node, 0, sizeof(constraint_node_t));
		if (useexpr) {
			node->expr = expr;
			useexpr = 0;
		} else {
			node->expr = constraint_expr_clone(expr);
		}
		if (!node->expr) {
			yyerror("out of memory");
			return -1;
		}
		node->permissions = 0;

		node->next = cladatum->constraints;
		cladatum->constraints = node;

		free(id);
	}

	while ((id = queue_remove(id_queue))) {
		ebitmap_for_each_bit(&classmap, enode, i) {
			if (ebitmap_node_get_bit(enode, i)) {
				cladatum = policydbp->class_val_to_struct[i];
				node = cladatum->constraints;

				perdatum =
				    (perm_datum_t *) hashtab_search(cladatum->
								    permissions.
								    table,
								    (hashtab_key_t)
								    id);
				if (!perdatum) {
					if (cladatum->comdatum) {
						perdatum =
						    (perm_datum_t *)
						    hashtab_search(cladatum->
								   comdatum->
								   permissions.
								   table,
								   (hashtab_key_t)
								   id);
					}
					if (!perdatum) {
						sprintf(errormsg,
							"permission %s is not defined",
							id);
						yyerror(errormsg);
						free(id);
						ebitmap_destroy(&classmap);
						return -1;
					}
				}
				node->permissions |=
				    (1 << (perdatum->s.value - 1));
			}
		}
		free(id);
	}

	ebitmap_destroy(&classmap);

	return 0;
}

static int define_validatetrans(constraint_expr_t * expr)
{
	struct constraint_node *node;
	char *id;
	class_datum_t *cladatum;
	ebitmap_t classmap;
	constraint_expr_t *e;
	int depth;
	unsigned char useexpr = 1;

	if (pass == 1) {
		while ((id = queue_remove(id_queue)))
			free(id);
		return 0;
	}

	depth = -1;
	for (e = expr; e; e = e->next) {
		switch (e->expr_type) {
		case CEXPR_NOT:
			if (depth < 0) {
				yyerror("illegal validatetrans expression");
				return -1;
			}
			break;
		case CEXPR_AND:
		case CEXPR_OR:
			if (depth < 1) {
				yyerror("illegal validatetrans expression");
				return -1;
			}
			depth--;
			break;
		case CEXPR_ATTR:
		case CEXPR_NAMES:
			if (depth == (CEXPR_MAXDEPTH - 1)) {
				yyerror("validatetrans expression is too deep");
				return -1;
			}
			depth++;
			break;
		default:
			yyerror("illegal validatetrans expression");
			return -1;
		}
	}
	if (depth != 0) {
		yyerror("illegal validatetrans expression");
		return -1;
	}

	ebitmap_init(&classmap);
	while ((id = queue_remove(id_queue))) {
		if (!is_id_in_scope(SYM_CLASSES, id)) {
			yyerror2("class %s is not within scope", id);
			free(id);
			return -1;
		}
		cladatum =
		    (class_datum_t *) hashtab_search(policydbp->p_classes.table,
						     (hashtab_key_t) id);
		if (!cladatum) {
			sprintf(errormsg, "class %s is not defined", id);
			ebitmap_destroy(&classmap);
			yyerror(errormsg);
			free(id);
			return -1;
		}
		if (ebitmap_set_bit(&classmap, (cladatum->s.value - 1), TRUE)) {
			yyerror("out of memory");
			ebitmap_destroy(&classmap);
			free(id);
			return -1;
		}

		node = malloc(sizeof(struct constraint_node));
		if (!node) {
			yyerror("out of memory");
			return -1;
		}
		memset(node, 0, sizeof(constraint_node_t));
		if (useexpr) {
			node->expr = expr;
			useexpr = 0;
		} else {
			node->expr = constraint_expr_clone(expr);
		}
		node->permissions = 0;

		node->next = cladatum->validatetrans;
		cladatum->validatetrans = node;

		free(id);
	}

	ebitmap_destroy(&classmap);

	return 0;
}

static uintptr_t
define_cexpr(uint32_t expr_type, uintptr_t arg1, uintptr_t arg2)
{
	struct constraint_expr *expr, *e1 = NULL, *e2;
	user_datum_t *user;
	role_datum_t *role;
	ebitmap_t negset;
	char *id;
	uint32_t val;
	int add = 1;

	if (pass == 1) {
		if (expr_type == CEXPR_NAMES) {
			while ((id = queue_remove(id_queue)))
				free(id);
		}
		return 1;	/* any non-NULL value */
	}

	if ((expr = malloc(sizeof(*expr))) == NULL ||
	    constraint_expr_init(expr) == -1) {
		yyerror("out of memory");
		free(expr);
		return 0;
	}
	expr->expr_type = expr_type;

	switch (expr_type) {
	case CEXPR_NOT:
		e1 = NULL;
		e2 = (struct constraint_expr *)arg1;
		while (e2) {
			e1 = e2;
			e2 = e2->next;
		}
		if (!e1 || e1->next) {
			yyerror("illegal constraint expression");
			constraint_expr_destroy(expr);
			return 0;
		}
		e1->next = expr;
		return arg1;
	case CEXPR_AND:
	case CEXPR_OR:
		e1 = NULL;
		e2 = (struct constraint_expr *)arg1;
		while (e2) {
			e1 = e2;
			e2 = e2->next;
		}
		if (!e1 || e1->next) {
			yyerror("illegal constraint expression");
			constraint_expr_destroy(expr);
			return 0;
		}
		e1->next = (struct constraint_expr *)arg2;

		e1 = NULL;
		e2 = (struct constraint_expr *)arg2;
		while (e2) {
			e1 = e2;
			e2 = e2->next;
		}
		if (!e1 || e1->next) {
			yyerror("illegal constraint expression");
			constraint_expr_destroy(expr);
			return 0;
		}
		e1->next = expr;
		return arg1;
	case CEXPR_ATTR:
		expr->attr = arg1;
		expr->op = arg2;
		return (uintptr_t) expr;
	case CEXPR_NAMES:
		add = 1;
		expr->attr = arg1;
		expr->op = arg2;
		ebitmap_init(&negset);
		while ((id = (char *)queue_remove(id_queue))) {
			if (expr->attr & CEXPR_USER) {
				if (!is_id_in_scope(SYM_USERS, id)) {
					yyerror2("user %s is not within scope",
						 id);
					constraint_expr_destroy(expr);
					return 0;
				}
				user =
				    (user_datum_t *) hashtab_search(policydbp->
								    p_users.
								    table,
								    (hashtab_key_t)
								    id);
				if (!user) {
					sprintf(errormsg, "unknown user %s",
						id);
					yyerror(errormsg);
					constraint_expr_destroy(expr);
					return 0;
				}
				val = user->s.value;
			} else if (expr->attr & CEXPR_ROLE) {
				if (!is_id_in_scope(SYM_ROLES, id)) {
					yyerror2("role %s is not within scope",
						 id);
					constraint_expr_destroy(expr);
					return 0;
				}
				role =
				    (role_datum_t *) hashtab_search(policydbp->
								    p_roles.
								    table,
								    (hashtab_key_t)
								    id);
				if (!role) {
					sprintf(errormsg, "unknown role %s",
						id);
					yyerror(errormsg);
					constraint_expr_destroy(expr);
					return 0;
				}
				val = role->s.value;
			} else if (expr->attr & CEXPR_TYPE) {
				if (set_types(expr->type_names, id, &add, 0)) {
					constraint_expr_destroy(expr);
					return 0;
				}
				continue;
			} else {
				yyerror("invalid constraint expression");
				constraint_expr_destroy(expr);
				return 0;
			}
			if (ebitmap_set_bit(&expr->names, val - 1, TRUE)) {
				yyerror("out of memory");
				ebitmap_destroy(&expr->names);
				constraint_expr_destroy(expr);
				return 0;
			}
			free(id);
		}
		ebitmap_destroy(&negset);
		return (uintptr_t) expr;
	default:
		yyerror("invalid constraint expression");
		constraint_expr_destroy(expr);
		return 0;
	}

	yyerror("invalid constraint expression");
	free(expr);
	return 0;
}

static int define_conditional(cond_expr_t * expr, avrule_t * t, avrule_t * f)
{
	cond_expr_t *e;
	int depth;
	cond_node_t cn, *cn_old;

	/* expression cannot be NULL */
	if (!expr) {
		yyerror("illegal conditional expression");
		return -1;
	}
	if (!t) {
		if (!f) {
			/* empty is fine, destroy expression and return */
			cond_expr_destroy(expr);
			return 0;
		}
		/* Invert */
		t = f;
		f = 0;
		expr = define_cond_expr(COND_NOT, expr, 0);
		if (!expr) {
			yyerror("unable to invert");
			return -1;
		}
	}

	/* verify expression */
	depth = -1;
	for (e = expr; e; e = e->next) {
		switch (e->expr_type) {
		case COND_NOT:
			if (depth < 0) {
				yyerror
				    ("illegal conditional expression; Bad NOT");
				return -1;
			}
			break;
		case COND_AND:
		case COND_OR:
		case COND_XOR:
		case COND_EQ:
		case COND_NEQ:
			if (depth < 1) {
				yyerror
				    ("illegal conditional expression; Bad binary op");
				return -1;
			}
			depth--;
			break;
		case COND_BOOL:
			if (depth == (COND_EXPR_MAXDEPTH - 1)) {
				yyerror
				    ("conditional expression is like totally too deep");
				return -1;
			}
			depth++;
			break;
		default:
			yyerror("illegal conditional expression");
			return -1;
		}
	}
	if (depth != 0) {
		yyerror("illegal conditional expression");
		return -1;
	}

	/*  use tmp conditional node to partially build new node */
	memset(&cn, 0, sizeof(cn));
	cn.expr = expr;
	cn.avtrue_list = t;
	cn.avfalse_list = f;

	/* normalize/precompute expression */
	if (cond_normalize_expr(policydbp, &cn) < 0) {
		yyerror("problem normalizing conditional expression");
		return -1;
	}

	/* get the existing conditional node, or create a new one */
	cn_old = get_current_cond_list(&cn);
	if (!cn_old) {
		return -1;
	}

	append_cond_list(&cn);

	/* note that there is no check here for duplicate rules, nor
	 * check that rule already exists in base -- that will be
	 * handled during conditional expansion, in expand.c */

	cn.avtrue_list = NULL;
	cn.avfalse_list = NULL;
	cond_node_destroy(&cn);

	return 0;
}

static cond_expr_t *define_cond_expr(uint32_t expr_type, void *arg1, void *arg2)
{
	struct cond_expr *expr, *e1 = NULL, *e2;
	cond_bool_datum_t *bool_var;
	char *id;

	/* expressions are handled in the second pass */
	if (pass == 1) {
		if (expr_type == COND_BOOL) {
			while ((id = queue_remove(id_queue))) {
				free(id);
			}
		}
		return (cond_expr_t *) 1;	/* any non-NULL value */
	}

	/* create a new expression struct */
	expr = malloc(sizeof(struct cond_expr));
	if (!expr) {
		yyerror("out of memory");
		return NULL;
	}
	memset(expr, 0, sizeof(cond_expr_t));
	expr->expr_type = expr_type;

	/* create the type asked for */
	switch (expr_type) {
	case COND_NOT:
		e1 = NULL;
		e2 = (struct cond_expr *)arg1;
		while (e2) {
			e1 = e2;
			e2 = e2->next;
		}
		if (!e1 || e1->next) {
			yyerror("illegal conditional NOT expression");
			free(expr);
			return NULL;
		}
		e1->next = expr;
		return (struct cond_expr *)arg1;
	case COND_AND:
	case COND_OR:
	case COND_XOR:
	case COND_EQ:
	case COND_NEQ:
		e1 = NULL;
		e2 = (struct cond_expr *)arg1;
		while (e2) {
			e1 = e2;
			e2 = e2->next;
		}
		if (!e1 || e1->next) {
			yyerror
			    ("illegal left side of conditional binary op expression");
			free(expr);
			return NULL;
		}
		e1->next = (struct cond_expr *)arg2;

		e1 = NULL;
		e2 = (struct cond_expr *)arg2;
		while (e2) {
			e1 = e2;
			e2 = e2->next;
		}
		if (!e1 || e1->next) {
			yyerror
			    ("illegal right side of conditional binary op expression");
			free(expr);
			return NULL;
		}
		e1->next = expr;
		return (struct cond_expr *)arg1;
	case COND_BOOL:
		id = (char *)queue_remove(id_queue);
		if (!id) {
			yyerror("bad conditional; expected boolean id");
			free(id);
			free(expr);
			return NULL;
		}
		if (!is_id_in_scope(SYM_BOOLS, id)) {
			yyerror2("boolean %s is not within scope", id);
			free(id);
			free(expr);
			return NULL;
		}
		bool_var =
		    (cond_bool_datum_t *) hashtab_search(policydbp->p_bools.
							 table,
							 (hashtab_key_t) id);
		if (!bool_var) {
			sprintf(errormsg,
				"unknown boolean %s in conditional expression",
				id);
			yyerror(errormsg);
			free(expr);
			free(id);
			return NULL;
		}
		expr->bool = bool_var->s.value;
		free(id);
		return expr;
	default:
		yyerror("illegal conditional expression");
		return NULL;
	}
}

static int set_user_roles(role_set_t * set, char *id)
{
	role_datum_t *r;
	unsigned int i;
	ebitmap_node_t *node;

	if (strcmp(id, "*") == 0) {
		free(id);
		yyerror("* is not allowed in user declarations");
		return -1;
	}

	if (strcmp(id, "~") == 0) {
		free(id);
		yyerror("~ is not allowed in user declarations");
		return -1;
	}

	if (!is_id_in_scope(SYM_ROLES, id)) {
		yyerror2("role %s is not within scope", id);
		free(id);
		return -1;
	}
	r = hashtab_search(policydbp->p_roles.table, id);
	if (!r) {
		sprintf(errormsg, "unknown role %s", id);
		yyerror(errormsg);
		free(id);
		return -1;
	}

	/* set the role and every role it dominates */
	ebitmap_for_each_bit(&r->dominates, node, i) {
		if (ebitmap_node_get_bit(node, i))
			if (ebitmap_set_bit(&set->roles, i, TRUE))
				goto oom;
	}
	free(id);
	return 0;
      oom:
	yyerror("out of memory");
	return -1;
}

static int
parse_categories(char *id, level_datum_t * levdatum, ebitmap_t * cats)
{
	cat_datum_t *cdatum;
	int range_start, range_end, i;

	if (id_has_dot(id)) {
		char *id_start = id;
		char *id_end = strchr(id, '.');

		*(id_end++) = '\0';

		cdatum = (cat_datum_t *) hashtab_search(policydbp->p_cats.table,
							(hashtab_key_t)
							id_start);
		if (!cdatum) {
			sprintf(errormsg, "unknown category %s", id_start);
			yyerror(errormsg);
			return -1;
		}
		range_start = cdatum->s.value - 1;
		cdatum = (cat_datum_t *) hashtab_search(policydbp->p_cats.table,
							(hashtab_key_t) id_end);
		if (!cdatum) {
			sprintf(errormsg, "unknown category %s", id_end);
			yyerror(errormsg);
			return -1;
		}
		range_end = cdatum->s.value - 1;

		if (range_end < range_start) {
			sprintf(errormsg, "category range is invalid");
			yyerror(errormsg);
			return -1;
		}
	} else {
		cdatum = (cat_datum_t *) hashtab_search(policydbp->p_cats.table,
							(hashtab_key_t) id);
		if (!cdatum) {
			sprintf(errormsg, "unknown category %s", id);
			yyerror(errormsg);
			return -1;
		}
		range_start = range_end = cdatum->s.value - 1;
	}

	for (i = range_start; i <= range_end; i++) {
		if (!ebitmap_get_bit(&levdatum->level->cat, i)) {
			uint32_t level_value = levdatum->level->sens - 1;
			policydb_index_others(NULL, policydbp, 0);
			sprintf(errormsg, "category %s can not be associated "
				"with level %s",
				policydbp->p_cat_val_to_name[i],
				policydbp->p_sens_val_to_name[level_value]);
			yyerror(errormsg);
			return -1;
		}
		if (ebitmap_set_bit(cats, i, TRUE)) {
			yyerror("out of memory");
			return -1;
		}
	}

	return 0;
}

static int
parse_semantic_categories(char *id, level_datum_t * levdatum,
                          mls_semantic_cat_t ** cats)
{
	cat_datum_t *cdatum;
	mls_semantic_cat_t *newcat;
	unsigned int range_start, range_end;

	if (id_has_dot(id)) {
		char *id_start = id;
		char *id_end = strchr(id, '.');

		*(id_end++) = '\0';

		cdatum = (cat_datum_t *) hashtab_search(policydbp->p_cats.table,
							(hashtab_key_t)
							id_start);
		if (!cdatum) {
			sprintf(errormsg, "unknown category %s", id_start);
			yyerror(errormsg);
			return -1;
		}
		range_start = cdatum->s.value;

		cdatum = (cat_datum_t *) hashtab_search(policydbp->p_cats.table,
							(hashtab_key_t) id_end);
		if (!cdatum) {
			sprintf(errormsg, "unknown category %s", id_end);
			yyerror(errormsg);
			return -1;
		}
		range_end = cdatum->s.value;
	} else {
		cdatum = (cat_datum_t *) hashtab_search(policydbp->p_cats.table,
							(hashtab_key_t) id);
		if (!cdatum) {
			sprintf(errormsg, "unknown category %s", id);
			yyerror(errormsg);
			return -1;
		}
		range_start = range_end = cdatum->s.value;
	}

	newcat = (mls_semantic_cat_t *) malloc(sizeof(mls_semantic_cat_t));
	if (!newcat) {
		yyerror("out of memory");
		return -1;
	}

	mls_semantic_cat_init(newcat);
	newcat->next = *cats;
	newcat->low = range_start;
	newcat->high = range_end;

	*cats = newcat;

	return 0;
}

static int define_user(void)
{
	char *id;
	user_datum_t *usrdatum;
	level_datum_t *levdatum;
	int l;

	if (pass == 1) {
		while ((id = queue_remove(id_queue)))
			free(id);
		if (mlspol) {
			while ((id = queue_remove(id_queue)))
				free(id);
			id = queue_remove(id_queue);
			free(id);
			for (l = 0; l < 2; l++) {
				while ((id = queue_remove(id_queue))) {
					free(id);
				}
				id = queue_remove(id_queue);
				if (!id)
					break;
				free(id);
			}
		}
		return 0;
	}

	if ((usrdatum = declare_user()) == NULL) {
		return -1;
	}

	while ((id = queue_remove(id_queue))) {
		if (set_user_roles(&usrdatum->roles, id))
			continue;
	}

	if (mlspol) {
		id = queue_remove(id_queue);
		if (!id) {
			yyerror("no default level specified for user");
			return -1;
		}

		levdatum = (level_datum_t *)
		    hashtab_search(policydbp->p_levels.table,
				   (hashtab_key_t) id);
		if (!levdatum) {
			sprintf(errormsg, "unknown sensitivity %s used in user"
				" level definition", id);
			yyerror(errormsg);
			free(id);
			return -1;
		}
		free(id);

		usrdatum->dfltlevel.sens = levdatum->level->sens;

		while ((id = queue_remove(id_queue))) {
			if (parse_semantic_categories(id, levdatum,
			                            &usrdatum->dfltlevel.cat)) {
				free(id);
				return -1;
			}
			free(id);
		}

		id = queue_remove(id_queue);

		for (l = 0; l < 2; l++) {
			levdatum = (level_datum_t *)
			    hashtab_search(policydbp->p_levels.table,
					   (hashtab_key_t) id);
			if (!levdatum) {
				sprintf(errormsg,
					"unknown sensitivity %s used in user range definition",
					id);
				yyerror(errormsg);
				free(id);
				return -1;
			}
			free(id);

			usrdatum->range.level[l].sens = levdatum->level->sens;

			while ((id = queue_remove(id_queue))) {
				if (parse_semantic_categories(id, levdatum,
				               &usrdatum->range.level[l].cat)) {
					free(id);
					return -1;
				}
				free(id);
			}

			id = queue_remove(id_queue);
			if (!id)
				break;
		}

		if (l == 0) {
			if (mls_semantic_level_cpy(&usrdatum->range.level[1],
			                           &usrdatum->range.level[0])) {
				yyerror("out of memory");
				return -1;
			}
		}
	}
	return 0;
}

static int parse_security_context(context_struct_t * c)
{
	char *id;
	role_datum_t *role;
	type_datum_t *typdatum;
	user_datum_t *usrdatum;
	level_datum_t *levdatum;
	int l;

	if (pass == 1) {
		id = queue_remove(id_queue);
		free(id);	/* user  */
		id = queue_remove(id_queue);
		free(id);	/* role  */
		id = queue_remove(id_queue);
		free(id);	/* type  */
		if (mlspol) {
			id = queue_remove(id_queue);
			free(id);
			for (l = 0; l < 2; l++) {
				while ((id = queue_remove(id_queue))) {
					free(id);
				}
				id = queue_remove(id_queue);
				if (!id)
					break;
				free(id);
			}
		}
		return 0;
	}

	context_init(c);

	/* extract the user */
	id = queue_remove(id_queue);
	if (!id) {
		yyerror("no effective user?");
		goto bad;
	}
	if (!is_id_in_scope(SYM_USERS, id)) {
		yyerror2("user %s is not within scope", id);
		free(id);
		goto bad;
	}
	usrdatum = (user_datum_t *) hashtab_search(policydbp->p_users.table,
						   (hashtab_key_t) id);
	if (!usrdatum) {
		sprintf(errormsg, "user %s is not defined", id);
		yyerror(errormsg);
		free(id);
		goto bad;
	}
	c->user = usrdatum->s.value;

	/* no need to keep the user name */
	free(id);

	/* extract the role */
	id = (char *)queue_remove(id_queue);
	if (!id) {
		yyerror("no role name for sid context definition?");
		return -1;
	}
	if (!is_id_in_scope(SYM_ROLES, id)) {
		yyerror2("role %s is not within scope", id);
		free(id);
		return -1;
	}
	role = (role_datum_t *) hashtab_search(policydbp->p_roles.table,
					       (hashtab_key_t) id);
	if (!role) {
		sprintf(errormsg, "role %s is not defined", id);
		yyerror(errormsg);
		free(id);
		return -1;
	}
	c->role = role->s.value;

	/* no need to keep the role name */
	free(id);

	/* extract the type */
	id = (char *)queue_remove(id_queue);
	if (!id) {
		yyerror("no type name for sid context definition?");
		return -1;
	}
	if (!is_id_in_scope(SYM_TYPES, id)) {
		yyerror2("type %s is not within scope", id);
		free(id);
		return -1;
	}
	typdatum = (type_datum_t *) hashtab_search(policydbp->p_types.table,
						   (hashtab_key_t) id);
	if (!typdatum || typdatum->flavor == TYPE_ATTRIB) {
		sprintf(errormsg, "type %s is not defined or is an attribute",
			id);
		yyerror(errormsg);
		free(id);
		return -1;
	}
	c->type = typdatum->s.value;

	/* no need to keep the type name */
	free(id);

	if (mlspol) {
		/* extract the low sensitivity */
		id = (char *)queue_head(id_queue);
		if (!id) {
			yyerror("no sensitivity name for sid context"
				" definition?");
			return -1;
		}

		id = (char *)queue_remove(id_queue);
		for (l = 0; l < 2; l++) {
			levdatum = (level_datum_t *)
			    hashtab_search(policydbp->p_levels.table,
					   (hashtab_key_t) id);
			if (!levdatum) {
				sprintf(errormsg, "Sensitivity %s is not "
					"defined", id);
				yyerror(errormsg);
				free(id);
				return -1;
			}
			free(id);
			c->range.level[l].sens = levdatum->level->sens;

			/* extract low category set */
			while ((id = queue_remove(id_queue))) {
				if (parse_categories(id, levdatum,
						     &c->range.level[l].cat)) {
					free(id);
					return -1;
				}
				free(id);
			}

			/* extract high sensitivity */
			id = (char *)queue_remove(id_queue);
			if (!id)
				break;
		}

		if (l == 0) {
			c->range.level[1].sens = c->range.level[0].sens;
			if (ebitmap_cpy(&c->range.level[1].cat,
					&c->range.level[0].cat)) {

				yyerror("out of memory");
				goto bad;
			}
		}
	}

	if (!policydb_context_isvalid(policydbp, c)) {
		yyerror("invalid security context");
		goto bad;
	}
	return 0;

      bad:
	context_destroy(c);

	return -1;
}

static int define_initial_sid_context(void)
{
	char *id;
	ocontext_t *c, *head;

	if (pass == 1) {
		id = (char *)queue_remove(id_queue);
		free(id);
		parse_security_context(NULL);
		return 0;
	}

	id = (char *)queue_remove(id_queue);
	if (!id) {
		yyerror("no sid name for SID context definition?");
		return -1;
	}
	head = policydbp->ocontexts[OCON_ISID];
	for (c = head; c; c = c->next) {
		if (!strcmp(id, c->u.name))
			break;
	}

	if (!c) {
		sprintf(errormsg, "SID %s is not defined", id);
		yyerror(errormsg);
		free(id);
		return -1;
	}
	if (c->context[0].user) {
		sprintf(errormsg, "The context for SID %s is multiply defined",
			id);
		yyerror(errormsg);
		free(id);
		return -1;
	}
	/* no need to keep the sid name */
	free(id);

	if (parse_security_context(&c->context[0]))
		return -1;

	return 0;
}

static int define_fs_context(unsigned int major, unsigned int minor)
{
	ocontext_t *newc, *c, *head;

	if (pass == 1) {
		parse_security_context(NULL);
		parse_security_context(NULL);
		return 0;
	}

	newc = (ocontext_t *) malloc(sizeof(ocontext_t));
	if (!newc) {
		yyerror("out of memory");
		return -1;
	}
	memset(newc, 0, sizeof(ocontext_t));

	newc->u.name = (char *)malloc(6);
	if (!newc->u.name) {
		yyerror("out of memory");
		free(newc);
		return -1;
	}
	sprintf(newc->u.name, "%02x:%02x", major, minor);

	if (parse_security_context(&newc->context[0])) {
		free(newc->u.name);
		free(newc);
		return -1;
	}
	if (parse_security_context(&newc->context[1])) {
		context_destroy(&newc->context[0]);
		free(newc->u.name);
		free(newc);
		return -1;
	}
	head = policydbp->ocontexts[OCON_FS];

	for (c = head; c; c = c->next) {
		if (!strcmp(newc->u.name, c->u.name)) {
			sprintf(errormsg, "duplicate entry for file system %s",
				newc->u.name);
			yyerror(errormsg);
			context_destroy(&newc->context[0]);
			context_destroy(&newc->context[1]);
			free(newc->u.name);
			free(newc);
			return -1;
		}
	}

	newc->next = head;
	policydbp->ocontexts[OCON_FS] = newc;

	return 0;
}

static int define_port_context(unsigned int low, unsigned int high)
{
	ocontext_t *newc, *c, *l, *head;
	unsigned int protocol;
	char *id;

	if (pass == 1) {
		id = (char *)queue_remove(id_queue);
		free(id);
		parse_security_context(NULL);
		return 0;
	}

	newc = malloc(sizeof(ocontext_t));
	if (!newc) {
		yyerror("out of memory");
		return -1;
	}
	memset(newc, 0, sizeof(ocontext_t));

	id = (char *)queue_remove(id_queue);
	if (!id) {
		free(newc);
		return -1;
	}
	if ((strcmp(id, "tcp") == 0) || (strcmp(id, "TCP") == 0)) {
		protocol = IPPROTO_TCP;
	} else if ((strcmp(id, "udp") == 0) || (strcmp(id, "UDP") == 0)) {
		protocol = IPPROTO_UDP;
	} else {
		sprintf(errormsg, "unrecognized protocol %s", id);
		yyerror(errormsg);
		free(newc);
		return -1;
	}

	newc->u.port.protocol = protocol;
	newc->u.port.low_port = low;
	newc->u.port.high_port = high;

	if (low > high) {
		sprintf(errormsg, "low port %d exceeds high port %d", low,
			high);
		yyerror(errormsg);
		free(newc);
		return -1;
	}

	if (parse_security_context(&newc->context[0])) {
		free(newc);
		return -1;
	}

	/* Preserve the matching order specified in the configuration. */
	head = policydbp->ocontexts[OCON_PORT];
	for (l = NULL, c = head; c; l = c, c = c->next) {
		unsigned int prot2, low2, high2;

		prot2 = c->u.port.protocol;
		low2 = c->u.port.low_port;
		high2 = c->u.port.high_port;
		if (protocol != prot2)
			continue;
		if (low == low2 && high == high2) {
			sprintf(errormsg,
				"duplicate portcon entry for %s %d-%d ", id,
				low, high);
			goto bad;
		}
		if (low2 <= low && high2 >= high) {
			sprintf(errormsg,
				"portcon entry for %s %d-%d hidden by earlier entry for %d-%d",
				id, low, high, low2, high2);
			goto bad;
		}
	}

	if (l)
		l->next = newc;
	else
		policydbp->ocontexts[OCON_PORT] = newc;

	return 0;

      bad:
	yyerror(errormsg);
	free(newc);
	return -1;
}

static int define_netif_context(void)
{
	ocontext_t *newc, *c, *head;

	if (pass == 1) {
		free(queue_remove(id_queue));
		parse_security_context(NULL);
		parse_security_context(NULL);
		return 0;
	}

	newc = (ocontext_t *) malloc(sizeof(ocontext_t));
	if (!newc) {
		yyerror("out of memory");
		return -1;
	}
	memset(newc, 0, sizeof(ocontext_t));

	newc->u.name = (char *)queue_remove(id_queue);
	if (!newc->u.name) {
		free(newc);
		return -1;
	}
	if (parse_security_context(&newc->context[0])) {
		free(newc->u.name);
		free(newc);
		return -1;
	}
	if (parse_security_context(&newc->context[1])) {
		context_destroy(&newc->context[0]);
		free(newc->u.name);
		free(newc);
		return -1;
	}
	head = policydbp->ocontexts[OCON_NETIF];

	for (c = head; c; c = c->next) {
		if (!strcmp(newc->u.name, c->u.name)) {
			sprintf(errormsg,
				"duplicate entry for network interface %s",
				newc->u.name);
			yyerror(errormsg);
			context_destroy(&newc->context[0]);
			context_destroy(&newc->context[1]);
			free(newc->u.name);
			free(newc);
			return -1;
		}
	}

	newc->next = head;
	policydbp->ocontexts[OCON_NETIF] = newc;
	return 0;
}

static int define_ipv4_node_context()
{	
	char *id;
	int rc = 0;
	struct in_addr addr, mask;
	ocontext_t *newc, *c, *l, *head;

	if (pass == 1) {
		free(queue_remove(id_queue));
		free(queue_remove(id_queue));
		parse_security_context(NULL);
		goto out;
	}

	id = queue_remove(id_queue);
	if (!id) {
		yyerror("failed to read ipv4 address");
		rc = -1;
		goto out;
	}

	rc = inet_pton(AF_INET, id, &addr);
	free(id);
	if (rc < 1) {
		yyerror("failed to parse ipv4 address");
		if (rc == 0)
			rc = -1;
		goto out;
	}

	id = queue_remove(id_queue);
	if (!id) {
		yyerror("failed to read ipv4 address");
		rc = -1;
		goto out;
	}

	rc = inet_pton(AF_INET, id, &mask);
	free(id);
	if (rc < 1) {
		yyerror("failed to parse ipv4 mask");
		if (rc == 0)
			rc = -1;
		goto out;
	}

	newc = malloc(sizeof(ocontext_t));
	if (!newc) {
		yyerror("out of memory");
		rc = -1;
		goto out;
	}

	memset(newc, 0, sizeof(ocontext_t));
	newc->u.node.addr = addr.s_addr;
	newc->u.node.mask = mask.s_addr;

	if (parse_security_context(&newc->context[0])) {
		free(newc);
		return -1;
	}

	/* Create order of most specific to least retaining
	   the order specified in the configuration. */
	head = policydbp->ocontexts[OCON_NODE];
	for (l = NULL, c = head; c; l = c, c = c->next) {
		if (newc->u.node.mask > c->u.node.mask)
			break;
	}

	newc->next = c;

	if (l)
		l->next = newc;
	else
		policydbp->ocontexts[OCON_NODE] = newc;
	rc = 0;
out:
	return rc;
}

static int define_ipv6_node_context(void)
{
	char *id;
	int rc = 0;
	struct in6_addr addr, mask;
	ocontext_t *newc, *c, *l, *head;

	if (pass == 1) {
		free(queue_remove(id_queue));
		free(queue_remove(id_queue));
		parse_security_context(NULL);
		goto out;
	}

	id = queue_remove(id_queue);
	if (!id) {
		yyerror("failed to read ipv6 address");
		rc = -1;
		goto out;
	}

	rc = inet_pton(AF_INET6, id, &addr);
	free(id);
	if (rc < 1) {
		yyerror("failed to parse ipv6 address");
		if (rc == 0)
			rc = -1;
		goto out;
	}

	id = queue_remove(id_queue);
	if (!id) {
		yyerror("failed to read ipv6 address");
		rc = -1;
		goto out;
	}

	rc = inet_pton(AF_INET6, id, &mask);
	free(id);
	if (rc < 1) {
		yyerror("failed to parse ipv6 mask");
		if (rc == 0)
			rc = -1;
		goto out;
	}

	newc = malloc(sizeof(ocontext_t));
	if (!newc) {
		yyerror("out of memory");
		rc = -1;
		goto out;
	}

	memset(newc, 0, sizeof(ocontext_t));
	memcpy(&newc->u.node6.addr[0], &addr.s6_addr32[0], 16);
	memcpy(&newc->u.node6.mask[0], &mask.s6_addr32[0], 16);

	if (parse_security_context(&newc->context[0])) {
		free(newc);
		rc = -1;
		goto out;
	}

	/* Create order of most specific to least retaining
	   the order specified in the configuration. */
	head = policydbp->ocontexts[OCON_NODE6];
	for (l = NULL, c = head; c; l = c, c = c->next) {
		if (memcmp(&newc->u.node6.mask, &c->u.node6.mask, 16) > 0)
			break;
	}

	newc->next = c;

	if (l)
		l->next = newc;
	else
		policydbp->ocontexts[OCON_NODE6] = newc;

	rc = 0;
      out:
	return rc;
}

static int define_fs_use(int behavior)
{
	ocontext_t *newc, *c, *head;

	if (pass == 1) {
		free(queue_remove(id_queue));
		parse_security_context(NULL);
		return 0;
	}

	newc = (ocontext_t *) malloc(sizeof(ocontext_t));
	if (!newc) {
		yyerror("out of memory");
		return -1;
	}
	memset(newc, 0, sizeof(ocontext_t));

	newc->u.name = (char *)queue_remove(id_queue);
	if (!newc->u.name) {
		free(newc);
		return -1;
	}
	newc->v.behavior = behavior;
	if (parse_security_context(&newc->context[0])) {
		free(newc->u.name);
		free(newc);
		return -1;
	}

	head = policydbp->ocontexts[OCON_FSUSE];

	for (c = head; c; c = c->next) {
		if (!strcmp(newc->u.name, c->u.name)) {
			sprintf(errormsg,
				"duplicate fs_use entry for filesystem type %s",
				newc->u.name);
			yyerror(errormsg);
			context_destroy(&newc->context[0]);
			free(newc->u.name);
			free(newc);
			return -1;
		}
	}

	newc->next = head;
	policydbp->ocontexts[OCON_FSUSE] = newc;
	return 0;
}

static int define_genfs_context_helper(char *fstype, int has_type)
{
	struct genfs *genfs_p, *genfs, *newgenfs;
	ocontext_t *newc, *c, *head, *p;
	char *type = NULL;
	int len, len2;

	if (pass == 1) {
		free(fstype);
		free(queue_remove(id_queue));
		if (has_type)
			free(queue_remove(id_queue));
		parse_security_context(NULL);
		return 0;
	}

	for (genfs_p = NULL, genfs = policydbp->genfs;
	     genfs; genfs_p = genfs, genfs = genfs->next) {
		if (strcmp(fstype, genfs->fstype) <= 0)
			break;
	}

	if (!genfs || strcmp(fstype, genfs->fstype)) {
		newgenfs = malloc(sizeof(struct genfs));
		if (!newgenfs) {
			yyerror("out of memory");
			return -1;
		}
		memset(newgenfs, 0, sizeof(struct genfs));
		newgenfs->fstype = fstype;
		newgenfs->next = genfs;
		if (genfs_p)
			genfs_p->next = newgenfs;
		else
			policydbp->genfs = newgenfs;
		genfs = newgenfs;
	}

	newc = (ocontext_t *) malloc(sizeof(ocontext_t));
	if (!newc) {
		yyerror("out of memory");
		return -1;
	}
	memset(newc, 0, sizeof(ocontext_t));

	newc->u.name = (char *)queue_remove(id_queue);
	if (!newc->u.name)
		goto fail;
	if (has_type) {
		type = (char *)queue_remove(id_queue);
		if (!type)
			goto fail;
		if (type[1] != 0) {
			sprintf(errormsg, "invalid type %s", type);
			yyerror(errormsg);
			goto fail;
		}
		switch (type[0]) {
		case 'b':
			newc->v.sclass = SECCLASS_BLK_FILE;
			break;
		case 'c':
			newc->v.sclass = SECCLASS_CHR_FILE;
			break;
		case 'd':
			newc->v.sclass = SECCLASS_DIR;
			break;
		case 'p':
			newc->v.sclass = SECCLASS_FIFO_FILE;
			break;
		case 'l':
			newc->v.sclass = SECCLASS_LNK_FILE;
			break;
		case 's':
			newc->v.sclass = SECCLASS_SOCK_FILE;
			break;
		case '-':
			newc->v.sclass = SECCLASS_FILE;
			break;
		default:
			sprintf(errormsg, "invalid type %s", type);
			yyerror(errormsg);
			goto fail;
		}
	}
	if (parse_security_context(&newc->context[0]))
		goto fail;

	head = genfs->head;

	for (p = NULL, c = head; c; p = c, c = c->next) {
		if (!strcmp(newc->u.name, c->u.name) &&
		    (!newc->v.sclass || !c->v.sclass
		     || newc->v.sclass == c->v.sclass)) {
			sprintf(errormsg,
				"duplicate entry for genfs entry (%s, %s)",
				fstype, newc->u.name);
			yyerror(errormsg);
			goto fail;
		}
		len = strlen(newc->u.name);
		len2 = strlen(c->u.name);
		if (len > len2)
			break;
	}

	newc->next = c;
	if (p)
		p->next = newc;
	else
		genfs->head = newc;
	return 0;
      fail:
	if (type)
		free(type);
	context_destroy(&newc->context[0]);
	if (fstype)
		free(fstype);
	if (newc->u.name)
		free(newc->u.name);
	free(newc);
	return -1;
}

static int define_genfs_context(int has_type)
{
	return define_genfs_context_helper(queue_remove(id_queue), has_type);
}

static int define_range_trans(int class_specified)
{
	char *id;
	level_datum_t *levdatum = 0;
	class_datum_t *cladatum;
	range_trans_rule_t *rule;
	int l, add = 1;

	if (!mlspol) {
		yyerror("range_transition rule in non-MLS configuration");
		return -1;
	}

	if (pass == 1) {
		while ((id = queue_remove(id_queue)))
			free(id);
		while ((id = queue_remove(id_queue)))
			free(id);
		if (class_specified)
			while ((id = queue_remove(id_queue)))
				free(id);
		id = queue_remove(id_queue);
		free(id);
		for (l = 0; l < 2; l++) {
			while ((id = queue_remove(id_queue))) {
				free(id);
			}
			id = queue_remove(id_queue);
			if (!id)
				break;
			free(id);
		}
		return 0;
	}

	rule = malloc(sizeof(struct range_trans_rule));
	if (!rule) {
		yyerror("out of memory");
		return -1;
	}
	range_trans_rule_init(rule);

	while ((id = queue_remove(id_queue))) {
		if (set_types(&rule->stypes, id, &add, 0))
			goto out;
	}
	add = 1;
	while ((id = queue_remove(id_queue))) {
		if (set_types(&rule->ttypes, id, &add, 0))
			goto out;
	}

	if (class_specified) {
		while ((id = queue_remove(id_queue))) {
			if (!is_id_in_scope(SYM_CLASSES, id)) {
				yyerror2("class %s is not within scope", id);
				free(id);
				goto out;
			}
			cladatum = hashtab_search(policydbp->p_classes.table,
			                          id);
			if (!cladatum) {
				sprintf(errormsg, "unknown class %s", id);
				yyerror(errormsg);
				goto out;
			}

			ebitmap_set_bit(&rule->tclasses, cladatum->s.value - 1,
			                TRUE);
			free(id);
		}
	} else {
		cladatum = hashtab_search(policydbp->p_classes.table,
		                          "process");
		if (!cladatum) {
			sprintf(errormsg, "could not find process class for "
			        "legacy range_transition statement\n");
			yyerror(errormsg);
			goto out;
		}

		ebitmap_set_bit(&rule->tclasses, cladatum->s.value - 1, TRUE);
	}

	id = (char *)queue_remove(id_queue);
	if (!id) {
		yyerror("no range in range_transition definition?");
		goto out;
	}
	for (l = 0; l < 2; l++) {
		levdatum = hashtab_search(policydbp->p_levels.table, id);
		if (!levdatum) {
			sprintf(errormsg,
				"unknown level %s used in range_transition "
			        "definition", id);
			yyerror(errormsg);
			free(id);
			goto out;
		}
		free(id);

		rule->trange.level[l].sens = levdatum->level->sens;

		while ((id = queue_remove(id_queue))) {
			if (parse_semantic_categories(id, levdatum,
			                          &rule->trange.level[l].cat)) {
				free(id);
				goto out;
			}
			free(id);
		}

		id = (char *)queue_remove(id_queue);
		if (!id)
			break;
	}
	if (l == 0) {
		if (mls_semantic_level_cpy(&rule->trange.level[1],
		                           &rule->trange.level[0])) {
			yyerror("out of memory");
			goto out;
		}
	}

	append_range_trans(rule);
	return 0;

out:
	range_trans_rule_destroy(rule);
	return -1;
}


/* FLASK */


