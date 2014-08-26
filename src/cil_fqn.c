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

#include "cil_internal.h"
#include "cil_log.h"
#include "cil_mem.h"
#include "cil_tree.h"
#include "cil_strpool.h"

struct cil_args_qualify {
	char fqparent[CIL_MAX_NAME_LENGTH];
	int len;
};

int __cil_fqn_qualify_last_child_helper(struct cil_tree_node *node, void *extra_args)
{
	struct cil_args_qualify *args = NULL;
	struct cil_symtab_datum *datum = NULL;
	int rc = SEPOL_ERR;

	if (node == NULL || extra_args == NULL) {
		rc = SEPOL_ERR;
		goto exit;
	}

	if (node->parent->flavor != CIL_BLOCK) {
		rc = SEPOL_OK;
		goto exit;
	}

	datum = node->parent->data;
	args = extra_args;
	args->len -= (strlen(datum->name) + 1);
	args->fqparent[args->len] = '\0';

	return SEPOL_OK;

exit:
	return rc;
}

int __cil_fqn_qualify_first_child_helper(struct cil_tree_node *node, void *extra_args)
{
	struct cil_args_qualify *args = NULL;
	struct cil_symtab_datum *datum = NULL;
	int rc = SEPOL_ERR;

	if (node == NULL || extra_args == NULL) {
		rc = SEPOL_ERR;
		goto exit;
	}

	if (node->parent->flavor != CIL_BLOCK) {
		rc = SEPOL_OK;
		goto exit;
	}

	args = extra_args;
	datum = node->parent->data;

	if (args->len + strlen(datum->name) + 1 >= CIL_MAX_NAME_LENGTH) {
		cil_log(CIL_INFO, "Fully qualified name too long at line %d of %s\n",
			node->line, node->path);
		rc = SEPOL_ERR;
		goto exit;
	}

	strcat(args->fqparent, datum->name);
	strcat(args->fqparent, ".");
	args->len += (strlen(datum->name) + 1);

	return SEPOL_OK;

exit:
	return rc;
}

int __cil_fqn_qualify_node_helper(struct cil_tree_node *node, uint32_t *finished, void *extra_args)
{
	struct cil_args_qualify *args = NULL;
	struct cil_symtab_datum *datum = NULL;
	char *fqn = NULL;
	int newlen = 0;
	int rc = SEPOL_ERR;

	if (node == NULL || finished == NULL || extra_args == NULL) {
		goto exit;
	}

	if (node->flavor < CIL_MIN_DECLARATIVE || node->flavor == CIL_PERM || node->flavor == CIL_MAP_PERM) {
		rc = SEPOL_OK;
		goto exit;
	}

	args = extra_args;
	datum = node->data;

	switch (node->flavor) {
	case CIL_OPTIONAL:
		if (datum->state == CIL_STATE_DISABLED) {
			*finished = CIL_TREE_SKIP_HEAD;
		}
		break;
	case CIL_MACRO:
		*finished = CIL_TREE_SKIP_HEAD;
		break;
	case CIL_BLOCK:
		if (((struct cil_block *)datum)->is_abstract == CIL_TRUE) {
			*finished = CIL_TREE_SKIP_HEAD;
		}
		break;
	case CIL_STRING:
	case CIL_NAME:
		/* Strings don't change */
		break;
	case CIL_TYPEATTRIBUTE:
	case CIL_ROLEATTRIBUTE:
	case CIL_BOOL:
	case CIL_CAT:
	case CIL_CATALIAS:
	case CIL_CATSET:
	case CIL_CLASS:
	case CIL_MAP_CLASS:
	case CIL_CLASSPERMISSION:
	case CIL_COMMON:
	case CIL_CONTEXT:
	case CIL_IPADDR:
	case CIL_LEVEL:
	case CIL_LEVELRANGE:
	case CIL_POLICYCAP:
	case CIL_ROLE:
	case CIL_SENS:
	case CIL_SENSALIAS:
	case CIL_SID:
	case CIL_TUNABLE:
	case CIL_TYPE:
	case CIL_TYPEALIAS:
	case CIL_USER:
		if (node != ((struct cil_symtab_datum*)node->data)->nodes->head->data) {
			break;
		}

		if (args->len == 0) {
			rc = SEPOL_OK;
			goto exit;
		}

		newlen = args->len + strlen(datum->name);
		if (newlen >= CIL_MAX_NAME_LENGTH) {
			cil_log(CIL_INFO, "Fully qualified name too long at line %d of %s\n",
				node->line, node->path);
			rc = SEPOL_ERR;
			goto exit;
		}
		fqn = cil_malloc(newlen + 1);
		strcpy(fqn, args->fqparent);
		strcat(fqn, datum->name);

		datum->name = cil_strpool_add(fqn);
		free(fqn);
		break;
	default:
		rc = SEPOL_ERR;
		goto exit;
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_fqn_qualify(struct cil_tree_node *root)
{
	struct cil_args_qualify extra_args;
	int rc = SEPOL_ERR;

	extra_args.fqparent[0] = '\0';
	extra_args.len = 0;

	rc = cil_tree_walk(root, __cil_fqn_qualify_node_helper, __cil_fqn_qualify_first_child_helper, __cil_fqn_qualify_last_child_helper, &extra_args);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	return rc;
}

