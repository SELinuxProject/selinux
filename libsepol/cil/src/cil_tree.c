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
			if (node->cl_head->data == CIL_KEY_SRC_INFO && node->cl_head->next != NULL && node->cl_head->next->next != NULL) {
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

int cil_tree_subtree_has_decl(struct cil_tree_node *node)
{
	while (node) {
		if (node->flavor >= CIL_MIN_DECLARATIVE) {
			return CIL_TRUE;
		}
		if (node->cl_head != NULL) {
			if (cil_tree_subtree_has_decl(node->cl_head))
				return CIL_TRUE;
		}
		node = node->next;
	}

	return CIL_FALSE;
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
