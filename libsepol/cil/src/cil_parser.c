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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sepol/errcodes.h>

#include "cil_internal.h"
#include "cil_log.h"
#include "cil_mem.h"
#include "cil_tree.h"
#include "cil_lexer.h"
#include "cil_strpool.h"
#include "cil_stack.h"

char *CIL_KEY_HLL_LMS;
char *CIL_KEY_HLL_LMX;
char *CIL_KEY_HLL_LME;

struct hll_info {
	int hll_lineno;
	int hll_expand;
};

static void push_hll_info(struct cil_stack *stack, int hll_lineno, int hll_expand)
{
	struct hll_info *new = cil_malloc(sizeof(*new));

	new->hll_lineno = hll_lineno;
	new->hll_expand = hll_expand;

	cil_stack_push(stack, CIL_NONE, new);
}

static void pop_hll_info(struct cil_stack *stack, int *hll_lineno, int *hll_expand)
{
	struct cil_stack_item *curr = cil_stack_pop(stack);
	struct cil_stack_item *prev = cil_stack_peek(stack);
	struct hll_info *old;

	free(curr->data);

	if (!prev) {
		*hll_lineno = -1;
		*hll_expand = -1;
	} else {
		old = prev->data;
		*hll_lineno = old->hll_lineno;
		*hll_expand = old->hll_expand;
	}
}

static void create_node(struct cil_tree_node **node, struct cil_tree_node *current, int line, int hll_line, void *value)
{
	cil_tree_node_init(node);
	(*node)->parent = current;
	(*node)->flavor = CIL_NODE;
	(*node)->line = line;
	(*node)->hll_line = hll_line;
	(*node)->data = value;
}

static void insert_node(struct cil_tree_node *node, struct cil_tree_node *current)
{
	if (current->cl_head == NULL) {
		current->cl_head = node;
	} else {
		current->cl_tail->next = node;
	}
	current->cl_tail = node;
}

static int add_hll_linemark(struct cil_tree_node **current, int *hll_lineno, int *hll_expand, struct cil_stack *stack, char *path)
{
	char *hll_type;
	struct cil_tree_node *node;
	struct token tok;
	char *hll_file;
	char *end = NULL;

	cil_lexer_next(&tok);
	hll_type = cil_strpool_add(tok.value);
	if (hll_type == CIL_KEY_HLL_LME) {
		if (cil_stack_is_empty(stack)) {
			cil_log(CIL_ERR, "Line mark end without start\n");
			goto exit;
		}
		pop_hll_info(stack, hll_lineno, hll_expand);
		*current = (*current)->parent;
	} else {
		create_node(&node, *current, tok.line, *hll_lineno, NULL);
		insert_node(node, *current);
		*current = node;

		create_node(&node, *current, tok.line, *hll_lineno, CIL_KEY_SRC_INFO);
		insert_node(node, *current);

		create_node(&node, *current, tok.line, *hll_lineno, CIL_KEY_SRC_HLL);
		insert_node(node, *current);

		if (hll_type == CIL_KEY_HLL_LMS) {
			*hll_expand = 0;
		} else if (hll_type == CIL_KEY_HLL_LMX) {
			*hll_expand = 1;
		} else {
			cil_log(CIL_ERR, "Invalid line mark syntax\n");
			goto exit;
		}

		cil_lexer_next(&tok);
		if (tok.type != SYMBOL) {
			cil_log(CIL_ERR, "Invalid line mark syntax\n");
			goto exit;
		}
		*hll_lineno = strtol(tok.value, &end, 10);
		if (errno == ERANGE || *end != '\0') {
			cil_log(CIL_ERR, "Problem parsing line number for line mark\n");
			goto exit;
		}

		push_hll_info(stack, *hll_lineno, *hll_expand);

		cil_lexer_next(&tok);
		if (tok.type != SYMBOL && tok.type != QSTRING) {
			cil_log(CIL_ERR, "Invalid line mark syntax\n");
			goto exit;
		}

		if (tok.type == QSTRING) {
			tok.value[strlen(tok.value) - 1] = '\0';
			tok.value = tok.value+1;
		}

		hll_file = cil_strpool_add(tok.value);

		create_node(&node, *current, tok.line, *hll_lineno, hll_file);
		insert_node(node, *current);
	}

	cil_lexer_next(&tok);
	if (tok.type != NEWLINE) {
		cil_log(CIL_ERR, "Invalid line mark syntax\n");
		goto exit;
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Problem with high-level line mark at line %d of %s\n", tok.line, path);
	return SEPOL_ERR;
}

static void add_cil_path(struct cil_tree_node **current, char *path)
{
	struct cil_tree_node *node;

	create_node(&node, *current, 0, 0, NULL);
	insert_node(node, *current);
	*current = node;

	create_node(&node, *current, 0, 0, CIL_KEY_SRC_INFO);
	insert_node(node, *current);

	create_node(&node, *current, 0, 0, CIL_KEY_SRC_CIL);
	insert_node(node, *current);

	create_node(&node, *current, 0, 0, path);
	insert_node(node, *current);
}

int cil_parser(char *_path, char *buffer, uint32_t size, struct cil_tree **parse_tree)
{

	int paren_count = 0;

	struct cil_tree *tree = NULL;
	struct cil_tree_node *node = NULL;
	struct cil_tree_node *current = NULL;
	char *path = cil_strpool_add(_path);
	struct cil_stack *stack;
	int hll_lineno = -1;
	int hll_expand = -1;
	struct token tok;
	int rc = SEPOL_OK;

	CIL_KEY_HLL_LMS = cil_strpool_add("lms");
	CIL_KEY_HLL_LMX = cil_strpool_add("lmx");
	CIL_KEY_HLL_LME = cil_strpool_add("lme");

	cil_stack_init(&stack);

	cil_lexer_setup(buffer, size);

	tree = *parse_tree;
	current = tree->root;

	add_cil_path(&current, path);

	do {
		cil_lexer_next(&tok);
		switch (tok.type) {
		case HLL_LINEMARK:
			rc = add_hll_linemark(&current, &hll_lineno, &hll_expand, stack, path);
			if (rc != SEPOL_OK) {
				goto exit;
			}
			break;
		case OPAREN:
			paren_count++;

			create_node(&node, current, tok.line, hll_lineno, NULL);
			insert_node(node, current);
			current = node;
			break;
		case CPAREN:
			paren_count--;
			if (paren_count < 0) {
				cil_log(CIL_ERR, "Close parenthesis without matching open at line %d of %s\n", tok.line, path);
				goto exit;
			}
			current = current->parent;
			break;
		case QSTRING:
			tok.value[strlen(tok.value) - 1] = '\0';
			tok.value = tok.value+1;
			/* FALLTHRU */
		case SYMBOL:
			if (paren_count == 0) {
				cil_log(CIL_ERR, "Symbol not inside parenthesis at line %d of %s\n", tok.line, path);
				goto exit;
			}

			create_node(&node, current, tok.line, hll_lineno, cil_strpool_add(tok.value));
			insert_node(node, current);
			break;
		case NEWLINE :
			if (!hll_expand) {
				hll_lineno++;
			}
			break;
		case COMMENT:
			while (tok.type != NEWLINE && tok.type != END_OF_FILE) {
				cil_lexer_next(&tok);
			}
			if (!hll_expand) {
				hll_lineno++;
			}
			if (tok.type != END_OF_FILE) {
				break;
			}
			/* FALLTHRU */
			// Fall through if EOF
		case END_OF_FILE:
			if (paren_count > 0) {
				cil_log(CIL_ERR, "Open parenthesis without matching close at line %d of %s\n", tok.line, path);
				goto exit;
			}
			if (!cil_stack_is_empty(stack)) {
				cil_log(CIL_ERR, "High-level language line marker start without close at line %d of %s\n", tok.line, path);
				goto exit;
			}
			break;
		case UNKNOWN:
			cil_log(CIL_ERR, "Invalid token '%s' at line %d of %s\n", tok.value, tok.line, path);
			goto exit;
		default:
			cil_log(CIL_ERR, "Unknown token type '%d' at line %d of %s\n", tok.type, tok.line, path);
			goto exit;
		}
	}
	while (tok.type != END_OF_FILE);

	cil_lexer_destroy();

	cil_stack_destroy(&stack);

	*parse_tree = tree;

	return SEPOL_OK;

exit:
	while (!cil_stack_is_empty(stack)) {
		pop_hll_info(stack, &hll_lineno, &hll_expand);
	}
	cil_stack_destroy(&stack);

	return SEPOL_ERR;
}
