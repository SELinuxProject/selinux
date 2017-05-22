/*
 * Copyright 2011 Tresys Technology, LLC. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 *    1. Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 * 
 *    2. Redistributions in binary form must reproduce the above copyright notice,
 *       this list of conditions and the following disclaimer in the documentation
 *       and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY TRESYS TECHNOLOGY, LLC ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL TRESYS TECHNOLOGY, LLC OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * The views and conclusions contained in the software and documentation are those
 * of the authors and should not be interpreted as representing official policies,
 * either expressed or implied, of Tresys Technology, LLC.
 */

#include <stdio.h>
#include <stdarg.h>
#include <inttypes.h>

#include <sepol/policydb/conditional.h>

#include "cil_internal.h"
#include "cil_flavor.h"
#include "cil_log.h"
#include "cil_tree.h"
#include "cil_list.h"
#include "cil_parser.h"
#include "cil_strpool.h"

void cil_tree_print_perms_list(struct cil_tree_node *current_perm);
void cil_tree_print_classperms(struct cil_classperms *cp);
void cil_tree_print_level(struct cil_level *level);
void cil_tree_print_levelrange(struct cil_levelrange *lvlrange);
void cil_tree_print_context(struct cil_context *context);
void cil_tree_print_expr_tree(struct cil_tree_node *expr_root);
void cil_tree_print_constrain(struct cil_constrain *cons);
void cil_tree_print_node(struct cil_tree_node *node);

__attribute__((noreturn)) __attribute__((format (printf, 1, 2))) void cil_tree_error(const char* msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	cil_vlog(CIL_ERR, msg, ap);
	va_end(ap);
	exit(1);
}

struct cil_tree_node *cil_tree_get_next_path(struct cil_tree_node *node, char **path, int* is_cil)
{
	if (!node) {
		return NULL;
	}

	node = node->parent;

	while (node) {
		if (node->flavor == CIL_NODE && node->data == NULL) {
			if (node->cl_head->data == CIL_KEY_SRC_INFO) {
				/* Parse Tree */
				*path = node->cl_head->next->next->data;
				*is_cil = (node->cl_head->next->data == CIL_KEY_SRC_CIL);
				return node;
			}
			node = node->parent;
		} else if (node->flavor == CIL_SRC_INFO) {
				/* AST */
				struct cil_src_info *info = node->data;
				*path = info->path;
				*is_cil = info->is_cil;
				return node;
		} else {
			if (node->flavor == CIL_CALL) {
				struct cil_call *call = node->data;
				node = NODE(call->macro);
			} else if (node->flavor == CIL_BLOCKINHERIT) {
				struct cil_blockinherit *inherit = node->data;
				node = NODE(inherit->block);
			} else {
				node = node->parent;
			}
		}
	}

	return NULL;
}

char *cil_tree_get_cil_path(struct cil_tree_node *node)
{
	char *path = NULL;
	int is_cil;

	while (node) {
		node = cil_tree_get_next_path(node, &path, &is_cil);
		if (node && is_cil) {
			return path;
		}
	}

	return NULL;
}

__attribute__((format (printf, 3, 4))) void cil_tree_log(struct cil_tree_node *node, enum cil_log_level lvl, const char* msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	cil_vlog(lvl, msg, ap);
	va_end(ap);

	if (node) {
		char *path = NULL;
		int is_cil;
		unsigned hll_line = node->hll_line;

		path = cil_tree_get_cil_path(node);

		if (path != NULL) {
			cil_log(lvl, " at %s:%d", path, node->line);
		}

		while (node) {
			node = cil_tree_get_next_path(node, &path, &is_cil);
			if (node && !is_cil) {
				cil_log(lvl," from %s:%d", path, hll_line);
				path = NULL;
				hll_line = node->hll_line;
			}
		}
	}

	cil_log(lvl,"\n");
}

int cil_tree_init(struct cil_tree **tree)
{
	struct cil_tree *new_tree = cil_malloc(sizeof(*new_tree));

	cil_tree_node_init(&new_tree->root);
	
	*tree = new_tree;
	
	return SEPOL_OK;
}

void cil_tree_destroy(struct cil_tree **tree)
{
	if (tree == NULL || *tree == NULL) {
		return;
	}

	cil_tree_subtree_destroy((*tree)->root);
	free(*tree);
	*tree = NULL;
}

void cil_tree_subtree_destroy(struct cil_tree_node *node)
{
	cil_tree_children_destroy(node);
	cil_tree_node_destroy(&node);
}

void cil_tree_children_destroy(struct cil_tree_node *node)
{
	struct cil_tree_node *start_node = node;
	struct cil_tree_node *next = NULL;

	if (node == NULL) {
		return;
	}

	if (node->cl_head != NULL) {
		node = node->cl_head;
	}

	while (node != start_node) {
		if (node->cl_head != NULL){
			next = node->cl_head;
		} else {
			if (node->next == NULL) {
				next = node->parent;
				if (node->parent != NULL) {
					node->parent->cl_head = NULL;
				}
				cil_tree_node_destroy(&node);
			} else {
				next = node->next;
				cil_tree_node_destroy(&node);
			}
		}
		node = next;
	}
}

void cil_tree_node_init(struct cil_tree_node **node)
{
	struct cil_tree_node *new_node = cil_malloc(sizeof(*new_node));
	new_node->cl_head = NULL;
	new_node->cl_tail = NULL;
	new_node->parent = NULL;
	new_node->data = NULL;
	new_node->next = NULL;
	new_node->flavor = CIL_ROOT;
	new_node->line = 0;
	new_node->hll_line = 0;

	*node = new_node;
}

void cil_tree_node_destroy(struct cil_tree_node **node)
{
	struct cil_symtab_datum *datum;

	if (node == NULL || *node == NULL) {
		return;
	}

	if ((*node)->flavor >= CIL_MIN_DECLARATIVE) {
		datum = (*node)->data;
		cil_symtab_datum_remove_node(datum, *node);
		if (datum->nodes == NULL) {
			cil_destroy_data(&(*node)->data, (*node)->flavor);
		}
	} else {
		cil_destroy_data(&(*node)->data, (*node)->flavor);
	}
	free(*node);
	*node = NULL;
}

/* Perform depth-first walk of the tree
   Parameters:
   start_node:          root node to start walking from
   process_node:        function to call when visiting a node
                        Takes parameters:
                            node:     node being visited
                            finished: boolean indicating to the tree walker that it should move on from this branch
                            extra_args:    additional data
   first_child:		Function to call before entering list of children
                        Takes parameters:
                            node:     node of first child
                            extra args:     additional data
   last_child:		Function to call when finished with the last child of a node's children
   extra_args:               any additional data to be passed to the helper functions
*/

int cil_tree_walk_core(struct cil_tree_node *node,
					   int (*process_node)(struct cil_tree_node *node, uint32_t *finished, void *extra_args),
					   int (*first_child)(struct cil_tree_node *node, void *extra_args), 
					   int (*last_child)(struct cil_tree_node *node, void *extra_args), 
					   void *extra_args)
{
	int rc = SEPOL_ERR;

	while (node) {
		uint32_t finished = CIL_TREE_SKIP_NOTHING;

		if (process_node != NULL) {
			rc = (*process_node)(node, &finished, extra_args);
			if (rc != SEPOL_OK) {
				cil_tree_log(node, CIL_INFO, "Problem");
				return rc;
			}
		}

		if (finished & CIL_TREE_SKIP_NEXT) {
			return SEPOL_OK;
		}

		if (node->cl_head != NULL && !(finished & CIL_TREE_SKIP_HEAD)) {
			rc = cil_tree_walk(node, process_node, first_child, last_child, extra_args);
			if (rc != SEPOL_OK) {
				return rc;
			}
		}

		node = node->next;
	}

	return SEPOL_OK;
}

int cil_tree_walk(struct cil_tree_node *node, 
				  int (*process_node)(struct cil_tree_node *node, uint32_t *finished, void *extra_args), 
				  int (*first_child)(struct cil_tree_node *node, void *extra_args), 
				  int (*last_child)(struct cil_tree_node *node, void *extra_args), 
				  void *extra_args)
{
	int rc = SEPOL_ERR;

	if (!node || !node->cl_head) {
		return SEPOL_OK;
	}

	if (first_child != NULL) {
		rc = (*first_child)(node->cl_head, extra_args);
		if (rc != SEPOL_OK) {
			cil_tree_log(node, CIL_INFO, "Problem");
			return rc;
		}
	}

	rc = cil_tree_walk_core(node->cl_head, process_node, first_child, last_child, extra_args);
	if (rc != SEPOL_OK) {
		return rc;
	}

	if (last_child != NULL) {
		rc = (*last_child)(node->cl_tail, extra_args);
		if (rc != SEPOL_OK) {
			cil_tree_log(node, CIL_INFO, "Problem");
			return rc;
		}
	}

	return SEPOL_OK;
}


/* Copied from cil_policy.c, but changed to prefix -- Need to refactor */
static int cil_expr_to_string(struct cil_list *expr, char **out)
{
	int rc = SEPOL_ERR;
	struct cil_list_item *curr;
	char *stack[COND_EXPR_MAXDEPTH] = {};
	int pos = 0;

	cil_list_for_each(curr, expr) {
		if (pos > COND_EXPR_MAXDEPTH) {
			rc = SEPOL_ERR;
			goto exit;
		}
		switch (curr->flavor) {
		case CIL_LIST:
			rc = cil_expr_to_string(curr->data, &stack[pos]);
			if (rc != SEPOL_OK) {
				goto exit;
			}
			pos++;
			break;
		case CIL_STRING:
			stack[pos] = curr->data;
			pos++;
			break;
		case CIL_DATUM:
			stack[pos] = ((struct cil_symtab_datum *)curr->data)->name;
			pos++;
			break;
		case CIL_OP: {
			int len;
			char *expr_str;
			enum cil_flavor op_flavor = *((enum cil_flavor *)curr->data);
			char *op_str = NULL;

			if (pos == 0) {
				rc = SEPOL_ERR;
				goto exit;
			}
			switch (op_flavor) {
			case CIL_AND:
				op_str = CIL_KEY_AND;
				break;
			case CIL_OR:
				op_str = CIL_KEY_OR;
				break;
			case CIL_NOT:
				op_str = CIL_KEY_NOT;
				break;
			case CIL_ALL:
				op_str = CIL_KEY_ALL;
				break;
			case CIL_EQ:
				op_str = CIL_KEY_EQ;
				break;
			case CIL_NEQ:
				op_str = CIL_KEY_NEQ;
				break;
			case CIL_XOR:
				op_str = CIL_KEY_XOR;
				break;
			case CIL_RANGE:
				op_str = CIL_KEY_RANGE;
				break;
			case CIL_CONS_DOM:
				op_str = CIL_KEY_CONS_DOM;
				break;
			case CIL_CONS_DOMBY:
				op_str = CIL_KEY_CONS_DOMBY;
				break;
			case CIL_CONS_INCOMP:
				op_str = CIL_KEY_CONS_INCOMP;
				break;
			default:
				cil_log(CIL_ERR, "Unknown operator in expression\n");
				goto exit;
				break;
			}
			if (op_flavor == CIL_NOT) {
				len = strlen(stack[pos-1]) + strlen(op_str) + 4;
				expr_str = cil_malloc(len);
				snprintf(expr_str, len, "(%s %s)", op_str, stack[pos-1]);
				free(stack[pos-1]);
				stack[pos-1] = NULL;
				pos--;
			} else {
				if (pos < 2) {
					rc = SEPOL_ERR;
					goto exit;
				}
				len = strlen(stack[pos-1]) + strlen(stack[pos-2]) + strlen(op_str) + 5;
				expr_str = cil_malloc(len);
				snprintf(expr_str, len, "(%s %s %s)", op_str, stack[pos-1], stack[pos-2]);
				free(stack[pos-2]);
				free(stack[pos-1]);
				stack[pos-2] = NULL;
				stack[pos-1] = NULL;
				pos -= 2;
			}
			stack[pos] = expr_str;
			pos++;
			break;
		}
		case CIL_CONS_OPERAND: {
			enum cil_flavor operand_flavor = *((enum cil_flavor *)curr->data);
			char *operand_str = NULL;
			switch (operand_flavor) {
			case CIL_CONS_U1:
				operand_str = CIL_KEY_CONS_U1;
				break;
			case CIL_CONS_U2:
				operand_str = CIL_KEY_CONS_U2;
				break;
			case CIL_CONS_U3:
				operand_str = CIL_KEY_CONS_U3;
				break;
			case CIL_CONS_T1:
				operand_str = CIL_KEY_CONS_T1;
				break;
			case CIL_CONS_T2:
				operand_str = CIL_KEY_CONS_T2;
				break;
			case CIL_CONS_T3:
				operand_str = CIL_KEY_CONS_T3;
				break;
			case CIL_CONS_R1:
				operand_str = CIL_KEY_CONS_R1;
				break;
			case CIL_CONS_R2:
				operand_str = CIL_KEY_CONS_R2;
				break;
			case CIL_CONS_R3:
				operand_str = CIL_KEY_CONS_R3;
				break;
			case CIL_CONS_L1:
				operand_str = CIL_KEY_CONS_L1;
				break;
			case CIL_CONS_L2:
				operand_str = CIL_KEY_CONS_L2;
				break;
			case CIL_CONS_H1:
				operand_str = CIL_KEY_CONS_H1;
				break;
			case CIL_CONS_H2:
				operand_str = CIL_KEY_CONS_H2;
				break;
			default:
				cil_log(CIL_ERR, "Unknown operand in expression\n");
				goto exit;
				break;
			}
			stack[pos] = operand_str;
			pos++;
			break;
		}
		default:
			cil_log(CIL_ERR, "Unknown flavor in expression\n");
			goto exit;
			break;
		}
	}

	*out = stack[0];

	return SEPOL_OK;

exit:
	return rc;
}

void cil_tree_print_expr(struct cil_list *datum_expr, struct cil_list *str_expr)
{
	char *expr_str;

	cil_log(CIL_INFO, "(");

	if (datum_expr != NULL) {
		cil_expr_to_string(datum_expr, &expr_str);
	} else {
		cil_expr_to_string(str_expr, &expr_str);
	}

	cil_log(CIL_INFO, "%s)", expr_str);
	free(expr_str);
}

void cil_tree_print_perms_list(struct cil_tree_node *current_perm)
{
	while (current_perm != NULL) {
		if (current_perm->flavor == CIL_PERM) {
			cil_log(CIL_INFO, " %s", ((struct cil_perm *)current_perm->data)->datum.name);
		} else if (current_perm->flavor == CIL_MAP_PERM) {
			cil_log(CIL_INFO, " %s", ((struct cil_perm*)current_perm->data)->datum.name);
		} else {
			cil_log(CIL_INFO, "\n\n perms list contained unexpected data type: %d\n", current_perm->flavor);
			break;
		}
		current_perm = current_perm->next;	
	}
}

void cil_tree_print_cats(struct cil_cats *cats)
{
	cil_tree_print_expr(cats->datum_expr, cats->str_expr);
}

void cil_tree_print_perm_strs(struct cil_list *perm_strs)
{
	struct cil_list_item *curr;

	if (perm_strs == NULL) {
		return;
	}

	cil_log(CIL_INFO, " (");

	cil_list_for_each(curr, perm_strs) {
		cil_log(CIL_INFO, " %s", (char*)curr->data);
	}

	cil_log(CIL_INFO, " )");
}


void cil_tree_print_classperms(struct cil_classperms *cp)
{
	if (cp == NULL) {
		return;
	}

	cil_log(CIL_INFO, " class: %s", cp->class_str);
	cil_log(CIL_INFO, ", perm_strs:");
	cil_tree_print_perm_strs(cp->perm_strs);
}

void cil_tree_print_classperms_set(struct cil_classperms_set *cp_set)
{
	if (cp_set == NULL) {
		return;
	}

	cil_log(CIL_INFO, " %s", cp_set->set_str);
}

void cil_tree_print_classperms_list(struct cil_list *cp_list)
{
	struct cil_list_item *i;

	if (cp_list == NULL) {
		return;
	}

	cil_list_for_each(i, cp_list) {
		if (i->flavor == CIL_CLASSPERMS) {
			cil_tree_print_classperms(i->data);
		} else {
			cil_tree_print_classperms_set(i->data);
		}
	}
}

void cil_tree_print_level(struct cil_level *level)
{
	if (level->sens != NULL) {
		cil_log(CIL_INFO, " %s", level->sens->datum.name);
	} else if (level->sens_str != NULL) {
		cil_log(CIL_INFO, " %s", level->sens_str);
	}

	cil_tree_print_cats(level->cats);

	return;
}

void cil_tree_print_levelrange(struct cil_levelrange *lvlrange)
{
	cil_log(CIL_INFO, " (");
	if (lvlrange->low != NULL) {
		cil_log(CIL_INFO, " (");
		cil_tree_print_level(lvlrange->low);
		cil_log(CIL_INFO, " )");
	} else if (lvlrange->low_str != NULL) {
		cil_log(CIL_INFO, " %s", lvlrange->low_str);
	}

	if (lvlrange->high != NULL) {
		cil_log(CIL_INFO, " (");
		cil_tree_print_level(lvlrange->high);
		cil_log(CIL_INFO, " )");
	} else if (lvlrange->high_str != NULL) {
		cil_log(CIL_INFO, " %s", lvlrange->high_str);
	}
	cil_log(CIL_INFO, " )");
}

void cil_tree_print_context(struct cil_context *context)
{
	cil_log(CIL_INFO, " (");
	if (context->user != NULL) {
		cil_log(CIL_INFO, " %s", context->user->datum.name);
	} else if (context->user_str != NULL) {
		cil_log(CIL_INFO, " %s", context->user_str);
	}

	if (context->role != NULL) {
		cil_log(CIL_INFO, " %s", context->role->datum.name);
	} else if (context->role_str != NULL) {
		cil_log(CIL_INFO, " %s", context->role_str);
	}

	if (context->type != NULL) {
		cil_log(CIL_INFO, " %s", ((struct cil_symtab_datum *)context->type)->name);
	} else if (context->type_str != NULL) {
		cil_log(CIL_INFO, " %s", context->type_str);
	}

	if (context->range != NULL) {
		cil_tree_print_levelrange(context->range);
	} else if (context->range_str != NULL) {
		cil_log(CIL_INFO, " %s", context->range_str);
	}

	cil_log(CIL_INFO, " )");

	return;
}

void cil_tree_print_constrain(struct cil_constrain *cons)
{
	cil_tree_print_classperms_list(cons->classperms);

	cil_tree_print_expr(cons->datum_expr, cons->str_expr);

	cil_log(CIL_INFO, "\n");
}

void cil_tree_print_node(struct cil_tree_node *node)
{
	if (node->data == NULL) {
		cil_log(CIL_INFO, "FLAVOR: %d", node->flavor);
		return;
	} else {
		switch( node->flavor ) {
		case CIL_BLOCK: {
			struct cil_block *block = node->data;
			cil_log(CIL_INFO, "BLOCK: %s\n", block->datum.name);
			return;
		}
		case CIL_BLOCKINHERIT: {
			struct cil_blockinherit *inherit = node->data;
			cil_log(CIL_INFO, "BLOCKINHERIT: %s\n", inherit->block_str);
			return;
		}
		case CIL_BLOCKABSTRACT: {
			struct cil_blockabstract *abstract = node->data;
			cil_log(CIL_INFO, "BLOCKABSTRACT: %s\n", abstract->block_str);
			return;
		}
		case CIL_IN: {
			struct cil_in *in = node->data;
			cil_log(CIL_INFO, "IN: %s\n", in->block_str);
			return;
		}
		case CIL_USER: {
			struct cil_user *user = node->data;
			cil_log(CIL_INFO, "USER: %s\n", user->datum.name);
			return;
		}
		case CIL_TYPE: {
			struct cil_type *type = node->data;
			cil_log(CIL_INFO, "TYPE: %s\n", type->datum.name);
			return;
		}
		case CIL_EXPANDTYPEATTRIBUTE: {
			struct cil_expandtypeattribute *attr = node->data;

			fprintf(stderr, "%s %u\n", __func__, __LINE__);
			cil_log(CIL_INFO, "(EXPANDTYPEATTRIBUTE ");
			cil_tree_print_expr(attr->attr_datums, attr->attr_strs);
			cil_log(CIL_INFO, "%s)\n",attr->expand ?
					CIL_KEY_CONDTRUE : CIL_KEY_CONDFALSE);

			return;
		}
		case CIL_TYPEATTRIBUTESET: {
			struct cil_typeattributeset *attr = node->data;

			cil_log(CIL_INFO, "(TYPEATTRIBUTESET %s ", attr->attr_str);

			cil_tree_print_expr(attr->datum_expr, attr->str_expr);

			cil_log(CIL_INFO, "\n");
			return;
		}
		case CIL_TYPEATTRIBUTE: {
			struct cil_typeattribute *attr = node->data;
			cil_log(CIL_INFO, "TYPEATTRIBUTE: %s\n", attr->datum.name);
			return;
		}
		case CIL_ROLE: {
			struct cil_role *role = node->data;
			cil_log(CIL_INFO, "ROLE: %s\n", role->datum.name);
			return;
		}
		case CIL_USERROLE: {
			struct cil_userrole *userrole = node->data;
			cil_log(CIL_INFO, "USERROLE:");
			struct cil_symtab_datum *datum = NULL;

			if (userrole->user != NULL) {
				datum = userrole->user;
				cil_log(CIL_INFO, " %s", datum->name);
			} else if (userrole->user_str != NULL) {
				cil_log(CIL_INFO, " %s", userrole->user_str);
			}

			if (userrole->role != NULL) {
				datum = userrole->role;
				cil_log(CIL_INFO, " %s", datum->name);
			} else if (userrole->role_str != NULL) {
				cil_log(CIL_INFO, " %s", userrole->role_str);
			}

			cil_log(CIL_INFO, "\n");
			return;
		}
		case CIL_USERLEVEL: {
			struct cil_userlevel *usrlvl = node->data;
			cil_log(CIL_INFO, "USERLEVEL:");

			if (usrlvl->user_str != NULL) {
				cil_log(CIL_INFO, " %s", usrlvl->user_str);
			}

			if (usrlvl->level != NULL) {
				cil_log(CIL_INFO, " (");
				cil_tree_print_level(usrlvl->level);
				cil_log(CIL_INFO, " )");
			} else if (usrlvl->level_str != NULL) {
				cil_log(CIL_INFO, " %s", usrlvl->level_str);
			}

			cil_log(CIL_INFO, "\n");
			return;
		}
		case CIL_USERRANGE: {
			struct cil_userrange *userrange = node->data;
			cil_log(CIL_INFO, "USERRANGE:");

			if (userrange->user_str != NULL) {
				cil_log(CIL_INFO, " %s", userrange->user_str);
			}

			if (userrange->range != NULL) {
				cil_log(CIL_INFO, " (");
				cil_tree_print_levelrange(userrange->range);
				cil_log(CIL_INFO, " )");
			} else if (userrange->range_str != NULL) {
				cil_log(CIL_INFO, " %s", userrange->range_str);
			}

			cil_log(CIL_INFO, "\n");
			return;
		}
		case CIL_USERBOUNDS: {
			struct cil_bounds *bnds = node->data;
			cil_log(CIL_INFO, "USERBOUNDS: user: %s, bounds: %s\n", bnds->parent_str, bnds->child_str);
			return;
		}
		case CIL_ROLETYPE: {
			struct cil_roletype *roletype = node->data;
			struct cil_symtab_datum *datum = NULL;
			cil_log(CIL_INFO, "ROLETYPE:");

			if (roletype->role != NULL) {
				datum = roletype->role;
				cil_log(CIL_INFO, " %s", datum->name);
			} else if (roletype->role_str != NULL) {
				cil_log(CIL_INFO, " %s", roletype->role_str);
			}

			if (roletype->type != NULL) {
				datum = roletype->type;
				cil_log(CIL_INFO, " %s", datum->name);
			} else if (roletype->type_str != NULL) {
				cil_log(CIL_INFO, " %s", roletype->type_str);
			}

			cil_log(CIL_INFO, "\n");
			return;
		}
		case CIL_ROLETRANSITION: {
			struct cil_roletransition *roletrans = node->data;
			cil_log(CIL_INFO, "ROLETRANSITION:");

			if (roletrans->src != NULL) {
				cil_log(CIL_INFO, " %s", roletrans->src->datum.name);
			} else {
				cil_log(CIL_INFO, " %s", roletrans->src_str);
			}

			if (roletrans->tgt != NULL) {
				cil_log(CIL_INFO, " %s", ((struct cil_symtab_datum *)roletrans->tgt)->name);
			} else {
				cil_log(CIL_INFO, " %s", roletrans->tgt_str);
			}
				
			if (roletrans->obj != NULL) {
				cil_log(CIL_INFO, " %s", roletrans->obj->datum.name);
			} else {
				cil_log(CIL_INFO, " %s", roletrans->obj_str);
			}

			if (roletrans->result != NULL) {
				cil_log(CIL_INFO, " %s\n", roletrans->result->datum.name);
			} else {
				cil_log(CIL_INFO, " %s\n", roletrans->result_str);
			}

			return;
		}
		case CIL_ROLEALLOW: {
			struct cil_roleallow *roleallow = node->data;
			cil_log(CIL_INFO, "ROLEALLOW:");

			if (roleallow->src != NULL) {
				cil_log(CIL_INFO, " %s", ((struct cil_symtab_datum*)roleallow->src)->name);
			} else {
				cil_log(CIL_INFO, " %s", roleallow->src_str);
			}

			if (roleallow->tgt != NULL) {
				cil_log(CIL_INFO, " %s", ((struct cil_symtab_datum*)roleallow->tgt)->name);
			} else {
				cil_log(CIL_INFO, " %s", roleallow->tgt_str);
			}

			cil_log(CIL_INFO, "\n");
			return;
		}
		case CIL_ROLEATTRIBUTESET: {
			struct cil_roleattributeset *attr = node->data;

			cil_log(CIL_INFO, "(ROLEATTRIBUTESET %s ", attr->attr_str);

			cil_tree_print_expr(attr->datum_expr, attr->str_expr);

			cil_log(CIL_INFO, "\n");
			return;
		}
		case CIL_ROLEATTRIBUTE: {
			struct cil_roleattribute *attr = node->data;
			cil_log(CIL_INFO, "ROLEATTRIBUTE: %s\n", attr->datum.name);
			return;
		}
		case CIL_USERATTRIBUTESET: {
			struct cil_userattributeset *attr = node->data;

			cil_log(CIL_INFO, "(USERATTRIBUTESET %s ", attr->attr_str);

			cil_tree_print_expr(attr->datum_expr, attr->str_expr);

			cil_log(CIL_INFO, "\n");
			return;
		}
		case CIL_USERATTRIBUTE: {
			struct cil_userattribute *attr = node->data;
			cil_log(CIL_INFO, "USERATTRIBUTE: %s\n", attr->datum.name);
			return;
		}
		case CIL_ROLEBOUNDS: {
			struct cil_bounds *bnds = node->data;
			cil_log(CIL_INFO, "ROLEBOUNDS: role: %s, bounds: %s\n", bnds->parent_str, bnds->child_str);
			return;
		}
		case CIL_CLASS: {
			struct cil_class *cls = node->data;
			cil_log(CIL_INFO, "CLASS: %s ", cls->datum.name);
				
			if (cls->common != NULL) {
				cil_log(CIL_INFO, "inherits: %s ", cls->common->datum.name);
			}
			cil_log(CIL_INFO, "(");
	
			cil_tree_print_perms_list(node->cl_head);
	
			cil_log(CIL_INFO, " )");
			return;
		}
		case CIL_CLASSORDER: {
			struct cil_classorder *classorder = node->data;
			struct cil_list_item *class;

			if (classorder->class_list_str == NULL) {
				cil_log(CIL_INFO, "CLASSORDER: ()\n");
				return;
			}

			cil_log(CIL_INFO, "CLASSORDER: (");
			cil_list_for_each(class, classorder->class_list_str) {
				cil_log(CIL_INFO, " %s", (char*)class->data);
			}
			cil_log(CIL_INFO, " )\n");
			return;
		}
		case CIL_COMMON: {
			struct cil_class *common = node->data;
			cil_log(CIL_INFO, "COMMON: %s (", common->datum.name);
		
			cil_tree_print_perms_list(node->cl_head);
	
			cil_log(CIL_INFO, " )");
			return;
		}
		case CIL_CLASSCOMMON: {
			struct cil_classcommon *clscom = node->data;

			cil_log(CIL_INFO, "CLASSCOMMON: class: %s, common: %s\n", clscom->class_str, clscom->common_str);

			return;
		}
		case CIL_CLASSPERMISSION: {
			struct cil_classpermission *cp = node->data;

			cil_log(CIL_INFO, "CLASSPERMISSION: %s", cp->datum.name);

			cil_log(CIL_INFO, "\n");

			return;
		}
		case CIL_CLASSPERMISSIONSET: {
			struct cil_classpermissionset *cps = node->data;

			cil_log(CIL_INFO, "CLASSPERMISSIONSET: %s", cps->set_str);

			cil_tree_print_classperms_list(cps->classperms);

			cil_log(CIL_INFO, "\n");

			return;
		}
		case CIL_MAP_CLASS: {
			struct cil_class *cm = node->data;
			cil_log(CIL_INFO, "MAP_CLASS: %s", cm->datum.name);

			cil_log(CIL_INFO, " (");
			cil_tree_print_perms_list(node->cl_head);
			cil_log(CIL_INFO, " )\n");

			return;
		}
		case CIL_MAP_PERM: {
			struct cil_perm *cmp = node->data;

			cil_log(CIL_INFO, "MAP_PERM: %s", cmp->datum.name);

			if (cmp->classperms == NULL) {
				cil_log(CIL_INFO, " perms: ()");
				return;
			}

			cil_log(CIL_INFO, " kernel class perms: (");

			cil_tree_print_classperms_list(cmp->classperms);

			cil_log(CIL_INFO, " )\n");

			return;
		}
		case CIL_CLASSMAPPING: {
			struct cil_classmapping *mapping = node->data;

			cil_log(CIL_INFO, "CLASSMAPPING: map class: %s, map perm: %s,", mapping->map_class_str, mapping->map_perm_str);

			cil_log(CIL_INFO, " (");

			cil_tree_print_classperms_list(mapping->classperms);

			cil_log(CIL_INFO, " )\n");
			return;
		}
		case CIL_BOOL: {
			struct cil_bool *boolean = node->data;
			cil_log(CIL_INFO, "BOOL: %s, value: %d\n", boolean->datum.name, boolean->value);
			return;
		}
		case CIL_TUNABLE: {
			struct cil_tunable *tunable = node->data;
			cil_log(CIL_INFO, "TUNABLE: %s, value: %d\n", tunable->datum.name, tunable->value);
			return;
		}
		case CIL_BOOLEANIF: {
			struct cil_booleanif *bif = node->data;

			cil_log(CIL_INFO, "(BOOLEANIF ");

			cil_tree_print_expr(bif->datum_expr, bif->str_expr);

			cil_log(CIL_INFO, " )\n");
			return;
		}
		case CIL_TUNABLEIF: {
			struct cil_tunableif *tif = node->data;

			cil_log(CIL_INFO, "(TUNABLEIF ");

			cil_tree_print_expr(tif->datum_expr, tif->str_expr);

			cil_log(CIL_INFO, " )\n");
			return;
		}
		case CIL_CONDBLOCK: {
			struct cil_condblock *cb = node->data;
			if (cb->flavor == CIL_CONDTRUE) {
				cil_log(CIL_INFO, "true\n");
			} else if (cb->flavor == CIL_CONDFALSE) {
				cil_log(CIL_INFO, "false\n");
			}
			return;
		}
		case CIL_ALL:
			cil_log(CIL_INFO, "all");
			return;
		case CIL_AND:
			cil_log(CIL_INFO, "&&");
			return;
		case CIL_OR:
			cil_log(CIL_INFO, "|| ");
			return;
		case CIL_NOT:
			cil_log(CIL_INFO, "!");
			return;
		case CIL_EQ:
			cil_log(CIL_INFO, "==");
			return;
		case CIL_NEQ:
			cil_log(CIL_INFO, "!=");
			return;
		case CIL_TYPEALIAS: {
			struct cil_alias *alias = node->data;
			cil_log(CIL_INFO, "TYPEALIAS: %s\n", alias->datum.name);
			return;
		}
		case CIL_TYPEALIASACTUAL: {
			struct cil_aliasactual *aliasactual = node->data;
			cil_log(CIL_INFO, "TYPEALIASACTUAL: type: %s, alias: %s\n", aliasactual->alias_str, aliasactual->actual_str);
			return;
		}
		case CIL_TYPEBOUNDS: {
			struct cil_bounds *bnds = node->data;
			cil_log(CIL_INFO, "TYPEBOUNDS: type: %s, bounds: %s\n", bnds->parent_str, bnds->child_str);
			return;
		}
		case CIL_TYPEPERMISSIVE: {
			struct cil_typepermissive *typeperm = node->data;

			if (typeperm->type != NULL) {
				cil_log(CIL_INFO, "TYPEPERMISSIVE: %s\n", ((struct cil_symtab_datum *)typeperm->type)->name);
			} else {
				cil_log(CIL_INFO, "TYPEPERMISSIVE: %s\n", typeperm->type_str);
			}

			return;
		}
		case CIL_NAMETYPETRANSITION: {
			struct cil_nametypetransition *nametypetrans = node->data;
			cil_log(CIL_INFO, "TYPETRANSITION:");

			if (nametypetrans->src != NULL) {
				cil_log(CIL_INFO, " %s", ((struct cil_symtab_datum *)nametypetrans->src)->name);
			} else {
				cil_log(CIL_INFO, " %s", nametypetrans->src_str);
			}

			if (nametypetrans->tgt != NULL) {
				cil_log(CIL_INFO, " %s", ((struct cil_symtab_datum *)nametypetrans->tgt)->name);
			} else {
				cil_log(CIL_INFO, " %s", nametypetrans->tgt_str);
			}

			if (nametypetrans->obj != NULL) {
				cil_log(CIL_INFO, " %s", nametypetrans->obj->datum.name);
			} else {
				cil_log(CIL_INFO, " %s", nametypetrans->obj_str);
			}

			cil_log(CIL_INFO, " %s\n", nametypetrans->name_str);

			if (nametypetrans->result != NULL) {
				cil_log(CIL_INFO, " %s", ((struct cil_symtab_datum *)nametypetrans->result)->name);
			} else {
				cil_log(CIL_INFO, " %s", nametypetrans->result_str);
			}

			return;
		}
		case CIL_RANGETRANSITION: {
			struct cil_rangetransition *rangetrans = node->data;
			cil_log(CIL_INFO, "RANGETRANSITION:");

			if (rangetrans->src != NULL) {
				cil_log(CIL_INFO, " %s", ((struct cil_symtab_datum *)rangetrans->src)->name);
			} else {
				cil_log(CIL_INFO, " %s", rangetrans->src_str);
			}

			if (rangetrans->exec != NULL) {
				cil_log(CIL_INFO, " %s", ((struct cil_symtab_datum *)rangetrans->exec)->name);
			} else {
				cil_log(CIL_INFO, " %s", rangetrans->exec_str);
			}

			if (rangetrans->obj != NULL) {
				cil_log(CIL_INFO, " %s", rangetrans->obj->datum.name);
			} else {
				cil_log(CIL_INFO, " %s", rangetrans->obj_str);
			}

			if (rangetrans->range != NULL) {
				cil_log(CIL_INFO, " (");
				cil_tree_print_levelrange(rangetrans->range);
				cil_log(CIL_INFO, " )");
			} else {
				cil_log(CIL_INFO, " %s", rangetrans->range_str);
			}

			cil_log(CIL_INFO, "\n");
			return;
		}
		case CIL_AVRULE: {
			struct cil_avrule *rule = node->data;
			switch (rule->rule_kind) {
			case CIL_AVRULE_ALLOWED:
				cil_log(CIL_INFO, "ALLOW:");
				break;
			case CIL_AVRULE_AUDITALLOW:
				cil_log(CIL_INFO, "AUDITALLOW:");
				break;
			case CIL_AVRULE_DONTAUDIT:
				cil_log(CIL_INFO, "DONTAUDIT:");
				break;
			case CIL_AVRULE_NEVERALLOW:
				cil_log(CIL_INFO, "NEVERALLOW:");
				break;
			}

			if (rule->src != NULL) {
				cil_log(CIL_INFO, " %s", ((struct cil_symtab_datum*)rule->src)->name);
			} else {
				cil_log(CIL_INFO, " %s", rule->src_str);
			}

			if (rule->tgt != NULL) {
				cil_log(CIL_INFO, " %s", ((struct cil_symtab_datum*)rule->tgt)->name);
			} else {
				cil_log(CIL_INFO, " %s", rule->tgt_str);
			}

			cil_tree_print_classperms_list(rule->perms.classperms);

			cil_log(CIL_INFO, "\n");

			return;
		}
		case CIL_TYPE_RULE: {
			struct cil_type_rule *rule = node->data;
			switch (rule->rule_kind) {
			case CIL_TYPE_TRANSITION:
				cil_log(CIL_INFO, "TYPETRANSITION:");
				break;
			case CIL_TYPE_MEMBER:
				cil_log(CIL_INFO, "TYPEMEMBER:");
				break;
			case CIL_TYPE_CHANGE:
				cil_log(CIL_INFO, "TYPECHANGE:");
				break;
			}

			if (rule->src != NULL) {
				cil_log(CIL_INFO, " %s", ((struct cil_symtab_datum *)rule->src)->name);
			} else {
				cil_log(CIL_INFO, " %s", rule->src_str);
			}

			if (rule->tgt != NULL) {
				cil_log(CIL_INFO, " %s", ((struct cil_symtab_datum *)rule->tgt)->name);
			} else {
				cil_log(CIL_INFO, " %s", rule->tgt_str);
			}

			if (rule->obj != NULL) {
				cil_log(CIL_INFO, " %s", rule->obj->datum.name);
			} else {
				cil_log(CIL_INFO, " %s", rule->obj_str);
			}

			if (rule->result != NULL) {
				cil_log(CIL_INFO, " %s\n", ((struct cil_symtab_datum *)rule->result)->name);
			} else {
				cil_log(CIL_INFO, " %s\n", rule->result_str);
			}

			return;
		}
		case CIL_SENS: {
			struct cil_sens *sens = node->data;
			cil_log(CIL_INFO, "SENSITIVITY: %s\n", sens->datum.name);
			return;
		}
		case CIL_SENSALIAS: {
			struct cil_alias *alias = node->data;
			cil_log(CIL_INFO, "SENSITIVITYALIAS: %s\n", alias->datum.name);
			return;
		}
		case CIL_SENSALIASACTUAL: {
			struct cil_aliasactual *aliasactual = node->data;
			cil_log(CIL_INFO, "SENSITIVITYALIAS: alias: %s, sensitivity: %s\n", aliasactual->alias_str, aliasactual->actual_str);

			return;
		}
		case CIL_CAT: {
			struct cil_cat *cat = node->data;
			cil_log(CIL_INFO, "CATEGORY: %s\n", cat->datum.name);
			return;
		}
		case CIL_CATALIAS: {
			struct cil_alias *alias = node->data;
			cil_log(CIL_INFO, "CATEGORYALIAS: %s\n", alias->datum.name);
			return;
		}
		case CIL_CATALIASACTUAL: {
			struct cil_aliasactual *aliasactual = node->data;
			cil_log(CIL_INFO, "CATEGORYALIAS: alias %s, category: %s\n", aliasactual->alias_str, aliasactual->actual_str);
			return;
		}
		case CIL_CATSET: {
			struct cil_catset *catset = node->data;

			cil_log(CIL_INFO, "CATSET: %s ",catset->datum.name);

			cil_tree_print_cats(catset->cats);

			return;
		}
		case CIL_CATORDER: {
			struct cil_catorder *catorder = node->data;
			struct cil_list_item *cat;

			if (catorder->cat_list_str == NULL) {
				cil_log(CIL_INFO, "CATORDER: ()\n");
				return;
			}

			cil_log(CIL_INFO, "CATORDER: (");
			cil_list_for_each(cat, catorder->cat_list_str) {
				cil_log(CIL_INFO, " %s", (char*)cat->data);
			}
			cil_log(CIL_INFO, " )\n");
			return;
		}
		case CIL_SENSCAT: {
			struct cil_senscat *senscat = node->data;

			cil_log(CIL_INFO, "SENSCAT: sens:");

			if (senscat->sens_str != NULL) {
				cil_log(CIL_INFO, " %s ", senscat->sens_str);
			} else {
				cil_log(CIL_INFO, " [processed]");
			}

			cil_tree_print_cats(senscat->cats);

			return;
		}
		case CIL_SENSITIVITYORDER: {
			struct cil_sensorder *sensorder = node->data;
			struct cil_list_item *sens;

			cil_log(CIL_INFO, "SENSITIVITYORDER: (");

			if (sensorder->sens_list_str != NULL) {
				cil_list_for_each(sens, sensorder->sens_list_str) {
					if (sens->flavor == CIL_LIST) {
						struct cil_list_item *sub;
						cil_log(CIL_INFO, " (");
						cil_list_for_each(sub, (struct cil_list*)sens->data) {
							cil_log(CIL_INFO, " %s", (char*)sub->data);
						}
						cil_log(CIL_INFO, " )");
					} else {
						cil_log(CIL_INFO, " %s", (char*)sens->data);
					}
				}
			}

			cil_log(CIL_INFO, " )\n");
			return;
		}
		case CIL_LEVEL: {
			struct cil_level *level = node->data;
			cil_log(CIL_INFO, "LEVEL %s:", level->datum.name); 
			cil_tree_print_level(level);
			cil_log(CIL_INFO, "\n");
			return;
		}
		case CIL_LEVELRANGE: {
			struct cil_levelrange *lvlrange = node->data;
			cil_log(CIL_INFO, "LEVELRANGE %s:", lvlrange->datum.name);
			cil_tree_print_levelrange(lvlrange);
			cil_log(CIL_INFO, "\n");
			return;
		}
		case CIL_CONSTRAIN: {
			struct cil_constrain *cons = node->data;
			cil_log(CIL_INFO, "CONSTRAIN: (");
			cil_tree_print_constrain(cons);
			return;
		}
		case CIL_MLSCONSTRAIN: {
			struct cil_constrain *cons = node->data;
			cil_log(CIL_INFO, "MLSCONSTRAIN: (");
			cil_tree_print_constrain(cons);
			return;
		}
		case CIL_VALIDATETRANS: {
			struct cil_validatetrans *vt = node->data;

			cil_log(CIL_INFO, "(VALIDATETRANS ");

			if (vt->class != NULL) {
				cil_log(CIL_INFO, "%s ", vt->class->datum.name);
			} else if (vt->class_str != NULL) {
				cil_log(CIL_INFO, "%s ", vt->class_str);
			}

			cil_tree_print_expr(vt->datum_expr, vt->str_expr);

			cil_log(CIL_INFO, ")\n");
			return;
		}
		case CIL_MLSVALIDATETRANS: {
			struct cil_validatetrans *vt = node->data;

			cil_log(CIL_INFO, "(MLSVALIDATETRANS ");

			if (vt->class != NULL) {
				cil_log(CIL_INFO, "%s ", vt->class->datum.name);
			} else if (vt->class_str != NULL) {
				cil_log(CIL_INFO, "%s ", vt->class_str);
			}

			cil_tree_print_expr(vt->datum_expr, vt->str_expr);

			cil_log(CIL_INFO, ")\n");
			return;
		}
		case CIL_CONTEXT: {
			struct cil_context *context = node->data;
			cil_log(CIL_INFO, "CONTEXT %s:", context->datum.name);
			cil_tree_print_context(context);
			cil_log(CIL_INFO, "\n");
			return;
		}
		case CIL_FILECON: {
			struct cil_filecon *filecon = node->data;
			cil_log(CIL_INFO, "FILECON:");
			cil_log(CIL_INFO, " %s %d", filecon->path_str, filecon->type);

			if (filecon->context != NULL) {
				cil_tree_print_context(filecon->context);
			} else if (filecon->context_str != NULL) {
				cil_log(CIL_INFO, " %s", filecon->context_str);
			}

			cil_log(CIL_INFO, "\n");
			return;

		}
		case CIL_IBPKEYCON: {
			struct cil_ibpkeycon *ibpkeycon = node->data;

			cil_log(CIL_INFO, "IBPKEYCON: %s", ibpkeycon->subnet_prefix_str);
			cil_log(CIL_INFO, " (%d %d) ", ibpkeycon->pkey_low, ibpkeycon->pkey_high);

			if (ibpkeycon->context)
				cil_tree_print_context(ibpkeycon->context);
			else if (ibpkeycon->context_str)
				cil_log(CIL_INFO, " %s", ibpkeycon->context_str);

			cil_log(CIL_INFO, "\n");
			return;
		}
		case CIL_PORTCON: {
			struct cil_portcon *portcon = node->data;
			cil_log(CIL_INFO, "PORTCON:");
			if (portcon->proto == CIL_PROTOCOL_UDP) {
				cil_log(CIL_INFO, " udp");
			} else if (portcon->proto == CIL_PROTOCOL_TCP) {
				cil_log(CIL_INFO, " tcp");
			} else if (portcon->proto == CIL_PROTOCOL_DCCP) {
				cil_log(CIL_INFO, " dccp");
			}
			cil_log(CIL_INFO, " (%d %d)", portcon->port_low, portcon->port_high);

			if (portcon->context != NULL) {
				cil_tree_print_context(portcon->context);
			} else if (portcon->context_str != NULL) {
				cil_log(CIL_INFO, " %s", portcon->context_str);
			}

			cil_log(CIL_INFO, "\n");
			return;
		}
		case CIL_NODECON: {
			struct cil_nodecon *nodecon = node->data;
			char buf[256];
				
			cil_log(CIL_INFO, "NODECON:");
				
			if (nodecon->addr) {
				inet_ntop(nodecon->addr->family, &nodecon->addr->ip, buf, 256);
				cil_log(CIL_INFO, " %s", buf);
			}  else {
				cil_log(CIL_INFO, " %s", nodecon->addr_str);
			}

			if (nodecon->mask) {
				inet_ntop(nodecon->mask->family, &nodecon->mask->ip, buf, 256);
				cil_log(CIL_INFO, " %s", buf);
			} else {
				cil_log(CIL_INFO, " %s", nodecon->mask_str);
			}
				
			if (nodecon->context != NULL) {
				cil_tree_print_context(nodecon->context);
			} else if (nodecon->context_str != NULL) {
				cil_log(CIL_INFO, " %s", nodecon->context_str);
			}

			cil_log(CIL_INFO, "\n");
			return;
		}
		case CIL_GENFSCON: {
			struct cil_genfscon *genfscon = node->data;
			cil_log(CIL_INFO, "GENFSCON:");
			cil_log(CIL_INFO, " %s %s", genfscon->fs_str, genfscon->path_str);

			if (genfscon->context != NULL) {
				cil_tree_print_context(genfscon->context);
			} else if (genfscon->context_str != NULL) {
				cil_log(CIL_INFO, " %s", genfscon->context_str);
			}

			cil_log(CIL_INFO, "\n");
			return;
		}
		case CIL_NETIFCON: {
			struct cil_netifcon *netifcon = node->data;
			cil_log(CIL_INFO, "NETIFCON %s", netifcon->interface_str);

			if (netifcon->if_context != NULL) {
				cil_tree_print_context(netifcon->if_context);
			} else if (netifcon->if_context_str != NULL) {
				cil_log(CIL_INFO, " %s", netifcon->if_context_str);
			}

			if (netifcon->packet_context != NULL) {
				cil_tree_print_context(netifcon->packet_context);
			} else if (netifcon->packet_context_str != NULL) {
				cil_log(CIL_INFO, " %s", netifcon->packet_context_str);
			}

			cil_log(CIL_INFO, "\n");
			return;
		}
		case CIL_IBENDPORTCON: {
			struct cil_ibendportcon *ibendportcon = node->data;

			cil_log(CIL_INFO, "IBENDPORTCON: %s %u ", ibendportcon->dev_name_str, ibendportcon->port);

			if (ibendportcon->context)
				cil_tree_print_context(ibendportcon->context);
			else if (ibendportcon->context_str)
				cil_log(CIL_INFO, " %s", ibendportcon->context_str);

			cil_log(CIL_INFO, "\n");
			return;
		}
		case CIL_PIRQCON: {
			struct cil_pirqcon *pirqcon = node->data;

			cil_log(CIL_INFO, "PIRQCON %d", pirqcon->pirq);
			if (pirqcon->context != NULL) {
				cil_tree_print_context(pirqcon->context);
			} else {
				cil_log(CIL_INFO, " %s", pirqcon->context_str);
			}

			cil_log(CIL_INFO, "\n");
			return;
		}
		case CIL_IOMEMCON: {
			struct cil_iomemcon *iomemcon = node->data;

			cil_log(CIL_INFO, "IOMEMCON ( %"PRId64" %"PRId64" )", iomemcon->iomem_low, iomemcon->iomem_high);
			if (iomemcon->context != NULL) {
				cil_tree_print_context(iomemcon->context);
			} else {
				cil_log(CIL_INFO, " %s", iomemcon->context_str);
			}

			cil_log(CIL_INFO, "\n");
			return;
		}
		case CIL_IOPORTCON: {
			struct cil_ioportcon *ioportcon = node->data;

			cil_log(CIL_INFO, "IOPORTCON ( %d %d )", ioportcon->ioport_low, ioportcon->ioport_high);
			if (ioportcon->context != NULL) {
				cil_tree_print_context(ioportcon->context);
			} else {
				cil_log(CIL_INFO, " %s", ioportcon->context_str);
			}

			cil_log(CIL_INFO, "\n");
			return;
		}
		case CIL_PCIDEVICECON: {
			struct cil_pcidevicecon *pcidevicecon = node->data;

			cil_log(CIL_INFO, "PCIDEVICECON %d", pcidevicecon->dev);
			if (pcidevicecon->context != NULL) {
				cil_tree_print_context(pcidevicecon->context);
			} else {
				cil_log(CIL_INFO, " %s", pcidevicecon->context_str);
			}

			cil_log(CIL_INFO, "\n");
			return;
		}
		case CIL_DEVICETREECON: {
			struct cil_devicetreecon *devicetreecon = node->data;

			cil_log(CIL_INFO, "DEVICETREECON %s", devicetreecon->path);
			if (devicetreecon->context != NULL) {
				cil_tree_print_context(devicetreecon->context);
			} else {
				cil_log(CIL_INFO, " %s", devicetreecon->context_str);
			}

			cil_log(CIL_INFO, "\n");
			return;
		}
		case CIL_FSUSE: {
			struct cil_fsuse *fsuse = node->data;
			cil_log(CIL_INFO, "FSUSE: ");

			if (fsuse->type == CIL_FSUSE_XATTR) {
				cil_log(CIL_INFO, "xattr ");
			} else if (fsuse->type == CIL_FSUSE_TASK) {
				cil_log(CIL_INFO, "task ");
			} else if (fsuse->type == CIL_FSUSE_TRANS) {
				cil_log(CIL_INFO, "trans ");
			} else {
				cil_log(CIL_INFO, "unknown ");
			}

			cil_log(CIL_INFO, "%s ", fsuse->fs_str);

			if (fsuse->context != NULL) {
				cil_tree_print_context(fsuse->context);
			} else {
				cil_log(CIL_INFO, " %s", fsuse->context_str);
			}

			cil_log(CIL_INFO, "\n");
			return;
		}
		case CIL_SID: {
			struct cil_sid *sid = node->data;
			cil_log(CIL_INFO, "SID: %s\n", sid->datum.name);
			return;
		}
		case CIL_SIDCONTEXT: {
			struct cil_sidcontext *sidcon = node->data;
			cil_log(CIL_INFO, "SIDCONTEXT: %s", sidcon->sid_str);

			if (sidcon->context != NULL) {
				cil_tree_print_context(sidcon->context);
			} else {
				cil_log(CIL_INFO, " %s", sidcon->context_str);
			}

			cil_log(CIL_INFO, "\n");
			return;
		}
		case CIL_SIDORDER: {
			struct cil_sidorder *sidorder = node->data;
			struct cil_list_item *sid;

			if (sidorder->sid_list_str == NULL) {
				cil_log(CIL_INFO, "SIDORDER: ()\n");
				return;
			}

			cil_log(CIL_INFO, "SIDORDER: (");
			cil_list_for_each(sid, sidorder->sid_list_str) {
				cil_log(CIL_INFO, " %s", (char*)sid->data);
			}
			cil_log(CIL_INFO, " )\n");
			return;
		}
		case CIL_POLICYCAP: {
			struct cil_policycap *polcap = node->data;
			cil_log(CIL_INFO, "POLICYCAP: %s\n", polcap->datum.name);
			return;
		}
		case CIL_MACRO: {
			struct cil_macro *macro = node->data;
			cil_log(CIL_INFO, "MACRO %s:", macro->datum.name);

			if (macro->params != NULL && macro->params->head != NULL) {
				struct cil_list_item *curr_param;
				cil_log(CIL_INFO, " parameters: (");
				cil_list_for_each(curr_param, macro->params) {
					cil_log(CIL_INFO, " flavor: %d, string: %s;", ((struct cil_param*)curr_param->data)->flavor, ((struct cil_param*)curr_param->data)->str);

				}
				cil_log(CIL_INFO, " )");
			}
			cil_log(CIL_INFO, "\n");

			return;
		}
		case CIL_CALL: {
			struct cil_call *call = node->data;
			cil_log(CIL_INFO, "CALL: macro name:");

			if (call->macro != NULL) {
				cil_log(CIL_INFO, " %s", call->macro->datum.name);
			} else {
				cil_log(CIL_INFO, " %s", call->macro_str);
			}

			if (call->args != NULL) {
				cil_log(CIL_INFO, ", args: ( ");
				struct cil_list_item *item;
				cil_list_for_each(item, call->args) {
					struct cil_symtab_datum *datum = ((struct cil_args*)item->data)->arg;
					if (datum != NULL) {
						if (datum->nodes != NULL && datum->nodes->head != NULL) {
							cil_tree_print_node((struct cil_tree_node*)datum->nodes->head->data);
						}
					} else if (((struct cil_args*)item->data)->arg_str != NULL) {
						switch (item->flavor) {
						case CIL_TYPE: cil_log(CIL_INFO, "type:"); break;
						case CIL_USER: cil_log(CIL_INFO, "user:"); break;
						case CIL_ROLE: cil_log(CIL_INFO, "role:"); break;
						case CIL_SENS: cil_log(CIL_INFO, "sensitivity:"); break;
						case CIL_CAT: cil_log(CIL_INFO, "category:"); break;
						case CIL_CATSET: cil_log(CIL_INFO, "categoryset:"); break;
						case CIL_LEVEL: cil_log(CIL_INFO, "level:"); break;
						case CIL_CLASS: cil_log(CIL_INFO, "class:"); break;
						default: break;
						}
						cil_log(CIL_INFO, "%s ", ((struct cil_args*)item->data)->arg_str);
					}
				}
				cil_log(CIL_INFO, ")");
			}

			cil_log(CIL_INFO, "\n");
			return;
		}	
		case CIL_OPTIONAL: {
			struct cil_optional *optional = node->data;
			cil_log(CIL_INFO, "OPTIONAL: %s\n", optional->datum.name);
			return;
		}
		case CIL_IPADDR: {
			struct cil_ipaddr *ipaddr = node->data;
			char buf[256];

			inet_ntop(ipaddr->family, &ipaddr->ip, buf, 256);
			cil_log(CIL_INFO, "IPADDR %s: %s\n", ipaddr->datum.name, buf);

			break;
		}
		default : {
			cil_log(CIL_INFO, "CIL FLAVOR: %d\n", node->flavor);
			return;
		}
		}
	}
}

void cil_tree_print(struct cil_tree_node *tree, uint32_t depth)
{
	struct cil_tree_node *current = NULL;
	current = tree;
	uint32_t x = 0;

	if (current != NULL) {
		if (current->cl_head == NULL) {
			if (current->flavor == CIL_NODE) {
				if (current->parent->cl_head == current) {
					cil_log(CIL_INFO, "%s", (char*)current->data);
				} else {
					cil_log(CIL_INFO, " %s", (char*)current->data);
				}
			} else if (current->flavor != CIL_PERM) {
				for (x = 0; x<depth; x++) {
					cil_log(CIL_INFO, "\t");
				}
				cil_tree_print_node(current);
			}
		} else {
			if (current->parent != NULL) {
				cil_log(CIL_INFO, "\n");
				for (x = 0; x<depth; x++) {
					cil_log(CIL_INFO, "\t");
				}
				cil_log(CIL_INFO, "(");

				if (current->flavor != CIL_NODE) {
					cil_tree_print_node(current);
				}
			}
			cil_tree_print(current->cl_head, depth + 1);
		}

		if (current->next == NULL) {
			if ((current->parent != NULL) && (current->parent->cl_tail == current) && (current->parent->parent != NULL)) {
				if (current->flavor == CIL_PERM) {
					cil_log(CIL_INFO, ")\n");
				} else if (current->flavor != CIL_NODE) {
					for (x = 0; x<depth-1; x++) {
						cil_log(CIL_INFO, "\t");
					}
					cil_log(CIL_INFO, ")\n");
				} else {
					cil_log(CIL_INFO, ")");
				}
			}

			if ((current->parent != NULL) && (current->parent->parent == NULL))
				cil_log(CIL_INFO, "\n\n");
		} else {
			cil_tree_print(current->next, depth);
		}
	} else {
		cil_log(CIL_INFO, "Tree is NULL\n");
	}
}
