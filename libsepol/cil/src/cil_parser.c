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

int cil_parser(char *_path, char *buffer, uint32_t size, struct cil_tree **parse_tree)
{

	int paren_count = 0;

	struct cil_tree *tree = NULL;
	struct cil_tree_node *node = NULL;
	struct cil_tree_node *item = NULL;
	struct cil_tree_node *current = NULL;
	char *path = cil_strpool_add(_path);

	struct token tok;

	cil_lexer_setup(buffer, size);

	tree = *parse_tree;
	current = tree->root;	

	do {
		cil_lexer_next(&tok);
		switch (tok.type) {
		case OPAREN:
			paren_count++;
			cil_tree_node_init(&node);
			node->parent = current;
			node->flavor = CIL_NODE;
			node->line = tok.line;
			node->path = path;
			if (current->cl_head == NULL) {
				current->cl_head = node;
			} else {
				current->cl_tail->next = node;
			}
			current->cl_tail = node;
			current = node;
			break;
		case CPAREN:
			paren_count--;
			if (paren_count < 0) {
				cil_log(CIL_ERR, "Close parenthesis without matching open at line %d of %s\n", tok.line, path);
				return SEPOL_ERR;
			}
			current = current->parent;
			break;
		case SYMBOL:
		case QSTRING:
			if (paren_count == 0) {
				cil_log(CIL_ERR, "Symbol not inside parenthesis at line %d of %s\n", tok.line, path);
				return SEPOL_ERR;
			}
			cil_tree_node_init(&item);
			item->parent = current;
			if (tok.type == QSTRING) {
				tok.value[strlen(tok.value) - 1] = '\0';
				item->data = cil_strpool_add(tok.value + 1);
			} else {
				item->data = cil_strpool_add(tok.value);
			}
			item->flavor = CIL_NODE;
			item->line = tok.line;
			item->path = path;
			if (current->cl_head == NULL) {
				current->cl_head = item;
			} else {
				current->cl_tail->next = item;
			}
			current->cl_tail = item;
			break;
		case END_OF_FILE:
			if (paren_count > 0) {
				cil_log(CIL_ERR, "Open parenthesis without matching close at line %d of %s\n", tok.line, path);
				return SEPOL_ERR;
			}
			break;
		case COMMENT:
			// ignore
			break;
		case UNKNOWN:
			cil_log(CIL_ERR, "Invalid token '%s' at line %d of %s\n", tok.value, tok.line, path);
			return SEPOL_ERR;
		default:
			cil_log(CIL_ERR, "Unknown token type '%d' at line %d of %s\n", tok.type, tok.line, path);
			return SEPOL_ERR;
		}
	}
	while (tok.type != END_OF_FILE);

	cil_lexer_destroy();

	*parse_tree = tree;

	return SEPOL_OK;
}
