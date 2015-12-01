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
#include <unistd.h>
#include <inttypes.h>

#include <sepol/policydb/conditional.h>
#include <sepol/errcodes.h>

#include "cil_internal.h"
#include "cil_flavor.h"
#include "cil_log.h"
#include "cil_mem.h"
#include "cil_tree.h"
#include "cil_list.h"
#include "cil_policy.h"
#include "cil_symtab.h"
#include "cil_strpool.h"

#define SEPOL_DONE			555

#define CLASS_DECL			0
#define ISIDS				1
#define COMMONS				2
#define CLASSES				3
#define INTERFACES			4
#define SENS				5
#define CATS				6
#define LEVELS				7
#define CONSTRAINS			8
#define TYPEATTRTYPES			9
#define ALIASES				10
#define ALLOWS				11
#define CONDS				12
#define USERROLES			13
#define SIDS				14
#define NETIFCONS			15 

#define BUFFER				1024
#define NUM_POLICY_FILES		16

struct cil_args_genpolicy {
	struct cil_list *users;
	struct cil_list *sens;
	struct cil_list *cats;
	FILE **file_arr;
};

struct cil_args_booleanif {
	FILE **file_arr;
	uint32_t *file_index;
};


int cil_expr_to_policy(FILE **file_arr, uint32_t file_index, struct cil_list *expr);

int cil_combine_policy(FILE **file_arr, FILE *policy_file)
{
	char temp[BUFFER];
	int i, rc, rc_read, rc_write;

	for(i=0; i<NUM_POLICY_FILES; i++) {
		fseek(file_arr[i], 0, SEEK_SET);
		while (!feof(file_arr[i])) {
			rc_read = fread(temp, 1, BUFFER, file_arr[i]);
			if (rc_read == 0 && ferror(file_arr[i])) {
				cil_log(CIL_ERR, "Error reading temp policy file\n");
				return SEPOL_ERR;
			}
			rc_write = 0;
			while (rc_read > rc_write) {
				rc = fwrite(temp+rc_write, 1, rc_read-rc_write, policy_file);
				rc_write += rc;
				if (rc == 0 && ferror(file_arr[i])) {
					cil_log(CIL_ERR, "Error writing to policy.conf\n");
					return SEPOL_ERR;
				}
			}
		}
	}

	return SEPOL_OK;
}

int cil_portcon_to_policy(FILE **file_arr, struct cil_sort *sort)
{
	uint32_t i = 0;

	for (i=0; i<sort->count; i++) {
		struct cil_portcon *portcon = (struct cil_portcon*)sort->array[i];
		fprintf(file_arr[NETIFCONS], "portcon ");
		if (portcon->proto == CIL_PROTOCOL_UDP) {
			fprintf(file_arr[NETIFCONS], "udp ");
		} else if (portcon->proto == CIL_PROTOCOL_TCP) {
			fprintf(file_arr[NETIFCONS], "tcp ");
		}
		fprintf(file_arr[NETIFCONS], "%d ", portcon->port_low);
		fprintf(file_arr[NETIFCONS], "%d ", portcon->port_high);
		cil_context_to_policy(file_arr, NETIFCONS, portcon->context);
		fprintf(file_arr[NETIFCONS], ";\n");
	}

	return SEPOL_OK;
}

int cil_genfscon_to_policy(FILE **file_arr, struct cil_sort *sort)
{
	uint32_t i = 0;

	for (i=0; i<sort->count; i++) {
		struct cil_genfscon *genfscon = (struct cil_genfscon*)sort->array[i];
		fprintf(file_arr[NETIFCONS], "genfscon %s ", genfscon->fs_str);
		fprintf(file_arr[NETIFCONS], "%s ", genfscon->path_str);
		cil_context_to_policy(file_arr, NETIFCONS, genfscon->context);
		fprintf(file_arr[NETIFCONS], ";\n");
	}

	return SEPOL_OK;
}

int cil_netifcon_to_policy(FILE **file_arr, struct cil_sort *sort)
{
	uint32_t i = 0;

	for (i=0; i<sort->count; i++) {
		struct cil_netifcon *netifcon = (struct cil_netifcon*)sort->array[i];
		fprintf(file_arr[NETIFCONS], "netifcon %s ", netifcon->interface_str);
		cil_context_to_policy(file_arr, NETIFCONS, netifcon->if_context);
		fprintf(file_arr[NETIFCONS], " ");
		cil_context_to_policy(file_arr, NETIFCONS, netifcon->packet_context);
		fprintf(file_arr[NETIFCONS], ";\n");
	}

	return SEPOL_OK;
}

int cil_nodecon_to_policy(FILE **file_arr, struct cil_sort *sort)
{
	uint32_t i = 0;
	int rc = SEPOL_ERR;

	for (i=0; i<sort->count; i++) {
		struct cil_nodecon *nodecon = (struct cil_nodecon*)sort->array[i];
		char *buf = NULL;
		errno = 0;
		if (nodecon->addr->family == AF_INET) {
			buf = cil_malloc(INET_ADDRSTRLEN);
			inet_ntop(nodecon->addr->family, &nodecon->addr->ip.v4, buf, INET_ADDRSTRLEN);
		} else if (nodecon->addr->family == AF_INET6) {
			buf = cil_malloc(INET6_ADDRSTRLEN);
			inet_ntop(nodecon->addr->family, &nodecon->addr->ip.v6, buf, INET6_ADDRSTRLEN);
		}

		if (errno != 0) {
			cil_log(CIL_INFO, "Failed to convert ip address to string\n");
			rc = SEPOL_ERR;
			goto exit;
		}

		fprintf(file_arr[NETIFCONS], "nodecon %s ", buf);
		free(buf);

		if (nodecon->mask->family == AF_INET) {
			buf = cil_malloc(INET_ADDRSTRLEN);
			inet_ntop(nodecon->mask->family, &nodecon->mask->ip.v4, buf, INET_ADDRSTRLEN);
		} else if (nodecon->mask->family == AF_INET6) {
			buf = cil_malloc(INET6_ADDRSTRLEN);
			inet_ntop(nodecon->mask->family, &nodecon->mask->ip.v6, buf, INET6_ADDRSTRLEN);
		}

		if (errno != 0) {
			cil_log(CIL_INFO, "Failed to convert mask to string\n");
			rc = SEPOL_ERR;
			goto exit;
		}

		fprintf(file_arr[NETIFCONS], "%s ", buf);
		free(buf);

		cil_context_to_policy(file_arr, NETIFCONS, nodecon->context);
		fprintf(file_arr[NETIFCONS], ";\n");
	}

	return SEPOL_OK;

exit:
	return rc;
}


int cil_pirqcon_to_policy(FILE **file_arr, struct cil_sort *sort)
{
	uint32_t i = 0;

	for (i = 0; i < sort->count; i++) {
		struct cil_pirqcon *pirqcon = (struct cil_pirqcon*)sort->array[i];
		fprintf(file_arr[NETIFCONS], "pirqcon %d ", pirqcon->pirq);
		cil_context_to_policy(file_arr, NETIFCONS, pirqcon->context);
		fprintf(file_arr[NETIFCONS], ";\n");
	}

	return SEPOL_OK;
}
int cil_iomemcon_to_policy(FILE **file_arr, struct cil_sort *sort)
{
	uint32_t i = 0;

	for (i = 0; i < sort->count; i++) {
		struct cil_iomemcon *iomemcon = (struct cil_iomemcon*)sort->array[i];
		fprintf(file_arr[NETIFCONS], "iomemcon %"PRId64"-%"PRId64" ", iomemcon->iomem_low, iomemcon->iomem_high);
		cil_context_to_policy(file_arr, NETIFCONS, iomemcon->context);
		fprintf(file_arr[NETIFCONS], ";\n");
	}

	return SEPOL_OK;
}

int cil_ioportcon_to_policy(FILE **file_arr, struct cil_sort *sort)
{
	uint32_t i = 0;

	for (i = 0; i < sort->count; i++) {
		struct cil_ioportcon *ioportcon = (struct cil_ioportcon*)sort->array[i];
		fprintf(file_arr[NETIFCONS], "ioportcon %d-%d ", ioportcon->ioport_low, ioportcon->ioport_high);
		cil_context_to_policy(file_arr, NETIFCONS, ioportcon->context);
		fprintf(file_arr[NETIFCONS], ";\n");
	}

	return SEPOL_OK;
}

int cil_pcidevicecon_to_policy(FILE **file_arr, struct cil_sort *sort)
{
	uint32_t i = 0;

	for (i = 0; i < sort->count; i++) {
		struct cil_pcidevicecon *pcidevicecon = (struct cil_pcidevicecon*)sort->array[i];
		fprintf(file_arr[NETIFCONS], "pcidevicecon %d ", pcidevicecon->dev);
		cil_context_to_policy(file_arr, NETIFCONS, pcidevicecon->context);
		fprintf(file_arr[NETIFCONS], ";\n");
	}

	return SEPOL_OK;
}

int cil_fsuse_to_policy(FILE **file_arr, struct cil_sort *sort)
{
	uint32_t i = 0;

	for (i=0; i<sort->count; i++) {
		struct cil_fsuse *fsuse = (struct cil_fsuse*)sort->array[i];
		if (fsuse->type == CIL_FSUSE_XATTR) {
			fprintf(file_arr[NETIFCONS], "fs_use_xattr ");
		} else if (fsuse->type == CIL_FSUSE_TASK) {
			fprintf(file_arr[NETIFCONS], "fs_use_task ");
		} else if (fsuse->type == CIL_FSUSE_TRANS) {
			fprintf(file_arr[NETIFCONS], "fs_use_trans ");
		} else {
			return SEPOL_ERR;
		}
		fprintf(file_arr[NETIFCONS], "%s ", fsuse->fs_str);
		cil_context_to_policy(file_arr, NETIFCONS, fsuse->context);
		fprintf(file_arr[NETIFCONS], ";\n");
	}

	return SEPOL_OK;
}

int cil_multimap_insert(struct cil_list *list, struct cil_symtab_datum *key, struct cil_symtab_datum *value, uint32_t key_flavor, uint32_t val_flavor)
{
	struct cil_list_item *curr_key;
	struct cil_multimap_item *new_data;

	if (list == NULL || key == NULL) {
		return SEPOL_ERR;
	}

	cil_list_for_each(curr_key, list) {
		struct cil_multimap_item *curr_multimap_item = curr_key->data;
		if (curr_multimap_item != NULL) {
			if (curr_multimap_item->key != NULL && curr_multimap_item->key == key) {
				struct cil_list_item *curr_value;
				cil_list_for_each(curr_value, curr_multimap_item->values) {
					if (curr_value == (struct cil_list_item*)value) {
						return SEPOL_OK;;
					}
				}
				cil_list_append(curr_multimap_item->values, val_flavor, value);
			}
		} else {
			cil_log(CIL_INFO, "No data in list item\n");
			return SEPOL_ERR;
		}
	}

	new_data = cil_malloc(sizeof(*new_data));
	new_data->key = key;
	cil_list_init(&new_data->values, CIL_LIST_ITEM);
	if (value != NULL) {
		cil_list_append(new_data->values, val_flavor, value);
	}
	cil_list_append(list, key_flavor, new_data);

	return SEPOL_OK;
}

int cil_userrole_to_policy(FILE **file_arr, struct cil_list *userroles)
{
	struct cil_list_item *current_user;

	if (userroles == NULL) {
		return SEPOL_OK;
	}
	
	cil_list_for_each(current_user, userroles) {
		struct cil_multimap_item *user_multimap_item = current_user->data;
		struct cil_list_item *current_role;
		if (user_multimap_item->values->head == NULL) {
			cil_log(CIL_INFO, "No roles associated with user %s\n",  
					user_multimap_item->key->name);
			return SEPOL_ERR;
		}

		fprintf(file_arr[USERROLES], "user %s roles {", user_multimap_item->key->name);

		cil_list_for_each(current_role, user_multimap_item->values) {
			fprintf(file_arr[USERROLES], " %s", ((struct cil_role*)current_role->data)->datum.name);
		}
		fprintf(file_arr[USERROLES], " };\n"); 
	}

	return SEPOL_OK;
}

int cil_cat_to_policy(FILE **file_arr, struct cil_list *cats)
{
	struct cil_list_item *curr_cat;

	if (cats == NULL) {
		return SEPOL_OK;
	}

	cil_list_for_each(curr_cat, cats) {
		struct cil_multimap_item *cat_multimap_item = curr_cat->data;
		fprintf(file_arr[CATS], "category %s", cat_multimap_item->key->name);
		if (cat_multimap_item->values->head == NULL) {
			fprintf(file_arr[CATS], ";\n");
		} else {
			struct cil_list_item *curr_catalias;
			fprintf(file_arr[CATS], " alias");
			cil_list_for_each(curr_catalias, cat_multimap_item->values) {
				fprintf(file_arr[CATS], " %s", ((struct cil_cat*)curr_catalias->data)->datum.name);
			}
			fprintf(file_arr[CATS], ";\n"); 
		}
	}

	return SEPOL_OK;
}

int cil_sens_to_policy(FILE **file_arr, struct cil_list *sens)
{
	struct cil_list_item *curr_sens;

	if (sens == NULL) {
		return SEPOL_OK;
	}

	cil_list_for_each(curr_sens, sens) {
		struct cil_multimap_item *sens_multimap_item = curr_sens->data;
		fprintf(file_arr[SENS], "sensitivity %s", sens_multimap_item->key->name);
		if (sens_multimap_item->values->head == NULL) 
			fprintf(file_arr[SENS], ";\n");
		else {
			struct cil_list_item *curr_sensalias;
			fprintf(file_arr[SENS], " alias");
			cil_list_for_each(curr_sensalias, sens_multimap_item->values) {
				fprintf(file_arr[SENS], " %s", ((struct cil_sens*)curr_sensalias->data)->datum.name);
			}
			fprintf(file_arr[SENS], ";\n"); 
		}
	}

	return SEPOL_OK;
}

void cil_cats_to_policy(FILE **file_arr, uint32_t file_index, struct cil_cats *cats)
{
	cil_expr_to_policy(file_arr, file_index, cats->datum_expr);
}

void cil_level_to_policy(FILE **file_arr, uint32_t file_index, struct cil_level *level)
{
	char *sens_str = level->sens->datum.name;

	fprintf(file_arr[file_index], "%s", sens_str);
	if (level->cats != NULL) {
		fprintf(file_arr[file_index], ":");
		cil_cats_to_policy(file_arr, file_index, level->cats);
	}
}

void cil_levelrange_to_policy(FILE **file_arr, uint32_t file_index, struct cil_levelrange *lvlrange)
{
	struct cil_level *low = lvlrange->low;
	struct cil_level *high = lvlrange->high;

	cil_level_to_policy(file_arr, file_index, low);
	fprintf(file_arr[file_index], "-");
	cil_level_to_policy(file_arr, file_index, high);
}

void cil_context_to_policy(FILE **file_arr, uint32_t file_index, struct cil_context *context)
{
	char *user_str = ((struct cil_symtab_datum*)context->user)->name;
	char *role_str = ((struct cil_symtab_datum*)context->role)->name;
	char *type_str = ((struct cil_symtab_datum*)context->type)->name;
	struct cil_levelrange *lvlrange = context->range;

	fprintf(file_arr[file_index], "%s:%s:%s:", user_str, role_str, type_str);
	cil_levelrange_to_policy(file_arr, file_index, lvlrange);
}

void cil_perms_to_policy(FILE **file_arr, uint32_t file_index, struct cil_list *list)
{
	struct cil_list_item *curr;

	fprintf(file_arr[file_index], " {");
	cil_list_for_each(curr, list) {
		switch (curr->flavor) {
		case CIL_LIST:
			cil_perms_to_policy(file_arr, file_index, curr->data);
			break;
		case CIL_STRING:
			fprintf(file_arr[file_index], " %s", (char *)curr->data);
			break;
		case CIL_DATUM:
			fprintf(file_arr[file_index], " %s", ((struct cil_symtab_datum *)curr->data)->name);
			break;
		case CIL_OP: {
			enum cil_flavor op_flavor = *((enum cil_flavor *)curr->data);
			char *op_str = NULL;

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
			case CIL_XOR:
				op_str = CIL_KEY_XOR;
				break;
			default:
				cil_log(CIL_ERR, "Unknown operator in expression\n");
				break;
			}
			fprintf(file_arr[file_index], " %s", op_str);
			break;
		}
		default:
			cil_log(CIL_ERR, "Unknown flavor in expression\n");
			break;
		}
	}
	fprintf(file_arr[file_index], " }");
}

void cil_constrain_to_policy_helper(FILE **file_arr, char *kind, struct cil_list *classperms, struct cil_list *expr)
{
	struct cil_list_item *curr;

	cil_list_for_each(curr, classperms) {
		if (curr->flavor == CIL_CLASSPERMS) {
			struct cil_classperms *cp = curr->data;
			if (FLAVOR(cp->class) == CIL_CLASS) {
				fprintf(file_arr[CONSTRAINS], "%s %s", kind, cp->class->datum.name);
				cil_perms_to_policy(file_arr, CONSTRAINS, cp->perms);
				fprintf(file_arr[CONSTRAINS], "\n\t");
				cil_expr_to_policy(file_arr, CONSTRAINS, expr);
				fprintf(file_arr[CONSTRAINS], ";\n");
			} else { /* MAP */
				struct cil_list_item *i = NULL;
				cil_list_for_each(i, cp->perms) {
					struct cil_perm *cmp = i->data;
					cil_constrain_to_policy_helper(file_arr, kind, cmp->classperms, expr);
				}
			}	
		} else { /* SET */
			struct cil_classperms_set *cp_set = curr->data;
			struct cil_classpermission *cp = cp_set->set;
			cil_constrain_to_policy_helper(file_arr, kind, cp->classperms, expr);
		}
	}
}

void cil_constrain_to_policy(FILE **file_arr, __attribute__((unused)) uint32_t file_index, struct cil_constrain *cons, enum cil_flavor flavor)
{
	char *kind = NULL;

	if (flavor == CIL_CONSTRAIN) {
		kind = CIL_KEY_CONSTRAIN;
	} else if (flavor == CIL_MLSCONSTRAIN) {
		kind = CIL_KEY_MLSCONSTRAIN;
	}

	cil_constrain_to_policy_helper(file_arr, kind, cons->classperms, cons->datum_expr);
}

void cil_avrule_to_policy_helper(FILE **file_arr, uint32_t file_index, const char *kind, const char *src, const char *tgt, struct cil_list *classperms)
{
	struct cil_list_item *i;

	cil_list_for_each(i, classperms) {
		if (i->flavor == CIL_CLASSPERMS) {
			struct cil_classperms *cp = i->data;
			if (FLAVOR(cp->class) == CIL_CLASS) {
				fprintf(file_arr[file_index], "%s %s %s: %s", kind, src, tgt, cp->class->datum.name);
				cil_perms_to_policy(file_arr, file_index, cp->perms);
				fprintf(file_arr[file_index], ";\n");
			} else { /* MAP */
				struct cil_list_item *j = NULL;
				cil_list_for_each(j, cp->perms) {
					struct cil_perm *cmp = j->data;
					cil_avrule_to_policy_helper(file_arr, file_index, kind, src, tgt, cmp->classperms);
				}
			}
		} else { /* SET */
			struct cil_list_item *j;
			struct cil_classperms_set *cp_set = i->data;
			struct cil_classpermission *cp = cp_set->set;
			cil_list_for_each(j, cp->classperms) {
				cil_avrule_to_policy_helper(file_arr, file_index, kind, src, tgt, j->data);
			}
		}
	}
}

int cil_avrule_to_policy(FILE **file_arr, uint32_t file_index, struct cil_avrule *rule)
{
	const char *kind_str = NULL;
	const char *src_str = DATUM(rule->src)->name;
	const char *tgt_str = DATUM(rule->tgt)->name;


	switch (rule->rule_kind) {
	case CIL_AVRULE_ALLOWED:
		kind_str = "allow";
		break;
	case CIL_AVRULE_AUDITALLOW:
		kind_str = "auditallow";
		break;
	case CIL_AVRULE_DONTAUDIT:
		kind_str = "dontaudit";
		break;
	case CIL_AVRULE_NEVERALLOW:
		kind_str = "neverallow";
		break;
	default :
		cil_log(CIL_INFO, "Unknown avrule with kind=%d src=%s tgt=%s\n",
				rule->rule_kind, src_str, tgt_str);
		return SEPOL_ERR;
	}

	cil_avrule_to_policy_helper(file_arr, file_index, kind_str, src_str, tgt_str, rule->perms.classperms);

	return SEPOL_OK;
}

int cil_typerule_to_policy(FILE **file_arr, __attribute__((unused)) uint32_t file_index, struct cil_type_rule *rule)
{
	char *src_str = ((struct cil_symtab_datum*)rule->src)->name;
	char *tgt_str = ((struct cil_symtab_datum*)rule->tgt)->name;
	char *obj_str = ((struct cil_symtab_datum*)rule->obj)->name;
	char *result_str = ((struct cil_symtab_datum*)rule->result)->name;
		
	switch (rule->rule_kind) {
	case CIL_TYPE_TRANSITION:
		fprintf(file_arr[ALLOWS], "type_transition %s %s : %s %s;\n", src_str, tgt_str, obj_str, result_str);
		break;
	case CIL_TYPE_CHANGE:
		fprintf(file_arr[ALLOWS], "type_change %s %s : %s %s\n;", src_str, tgt_str, obj_str, result_str);
		break;
	case CIL_TYPE_MEMBER:
		fprintf(file_arr[ALLOWS], "type_member %s %s : %s %s;\n", src_str, tgt_str, obj_str, result_str);
		break;
	default:
		cil_log(CIL_INFO, "Unknown type_rule\n");
		return SEPOL_ERR;
	}

	return SEPOL_OK;
}

int cil_nametypetransition_to_policy(FILE **file_arr, uint32_t file_index, struct cil_nametypetransition *nametypetrans)
{
	char *src_str = ((struct cil_symtab_datum*)nametypetrans->src)->name;
	char *tgt_str = ((struct cil_symtab_datum*)nametypetrans->tgt)->name;
	char *obj_str = ((struct cil_symtab_datum*)nametypetrans->obj)->name;
	char *result_str = ((struct cil_symtab_datum*)nametypetrans->result)->name;

	fprintf(file_arr[file_index], "type_transition %s %s : %s %s %s;\n", src_str, tgt_str, obj_str, result_str, nametypetrans->name_str);
	return SEPOL_OK;
}

static int cil_expr_to_string(struct cil_list *expr, char **out)
{
	int rc = SEPOL_ERR;
	struct cil_list_item *curr;
	char *stack[COND_EXPR_MAXDEPTH] = {};
	int pos = 0;
	int i;

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
				snprintf(expr_str, len, "(%s %s %s)", stack[pos-1], op_str, stack[pos-2]);
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
	for (i = 0; i < pos; i++) {
		free(stack[i]);
	}
	return rc;
}

int cil_expr_to_policy(FILE **file_arr, uint32_t file_index, struct cil_list *expr)
{
	int rc = SEPOL_ERR;
	char *str_out;

	rc = cil_expr_to_string(expr, &str_out);
	if (rc != SEPOL_OK) {
		goto out;
	}
	fprintf(file_arr[file_index], "%s", str_out);
	free(str_out);

	return SEPOL_OK;

out:
	return rc;
}

int __cil_booleanif_node_helper(struct cil_tree_node *node, __attribute__((unused)) uint32_t *finished, void *extra_args)
{
	int rc = SEPOL_ERR;
	struct cil_args_booleanif *args;
	FILE **file_arr;
	uint32_t *file_index;

	args = extra_args;
	file_arr = args->file_arr;
	file_index = args->file_index;

	switch (node->flavor) {
	case CIL_AVRULE:
		rc = cil_avrule_to_policy(file_arr, *file_index, (struct cil_avrule*)node->data);
		if (rc != SEPOL_OK) {
			cil_log(CIL_INFO, "cil_avrule_to_policy failed, rc: %d\n", rc);
			return rc;
		}
		break;
	case CIL_TYPE_RULE:
		rc = cil_typerule_to_policy(file_arr, *file_index, (struct cil_type_rule*)node->data);
		if (rc != SEPOL_OK) {
			cil_log(CIL_INFO, "cil_typerule_to_policy failed, rc: %d\n", rc);
			return rc;
		}
		break;
	case CIL_FALSE:
		fprintf(file_arr[*file_index], "else {\n");
		break;
	case CIL_TRUE:
		break;
	default:
		return SEPOL_ERR;
	}

	return SEPOL_OK;
}

int __cil_booleanif_last_child_helper(struct cil_tree_node *node, void *extra_args)
{
	struct cil_args_booleanif *args;
	FILE **file_arr;
	uint32_t *file_index;

	args = extra_args;
	file_arr = args->file_arr;
	file_index = args->file_index;

	if (node->parent->flavor == CIL_FALSE) {
		fprintf(file_arr[*file_index], "}\n");
	}
	
	return SEPOL_OK;
}

int cil_booleanif_to_policy(FILE **file_arr, uint32_t file_index, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	struct cil_booleanif *bif = node->data;
	struct cil_list *expr = bif->datum_expr;
	struct cil_args_booleanif extra_args;
	struct cil_tree_node *true_node = NULL;
	struct cil_tree_node *false_node = NULL;
	struct cil_condblock *cb = NULL;

	extra_args.file_arr = file_arr;
	extra_args.file_index = &file_index;;

	fprintf(file_arr[file_index], "if ");

	rc = cil_expr_to_policy(file_arr, file_index, expr);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Failed to write expression\n");
		return rc;
	}

	if (node->cl_head != NULL && node->cl_head->flavor == CIL_CONDBLOCK) {
		cb = node->cl_head->data;
		if (cb->flavor == CIL_CONDTRUE) {
			true_node = node->cl_head;
		} else if (cb->flavor == CIL_CONDFALSE) {
			false_node = node->cl_head;
		}
	}

	if (node->cl_head != NULL && node->cl_head->next != NULL && node->cl_head->next->flavor == CIL_CONDBLOCK) {
		cb = node->cl_head->next->data;
		if (cb->flavor == CIL_CONDTRUE) {
			true_node = node->cl_head->next;
		} else if (cb->flavor == CIL_CONDFALSE) {
			false_node = node->cl_head->next;
		}
	}

	fprintf(file_arr[file_index], "{\n");
	if (true_node != NULL) {
		rc = cil_tree_walk(true_node, __cil_booleanif_node_helper, __cil_booleanif_last_child_helper, NULL, &extra_args);
		if (rc != SEPOL_OK) {
			cil_log(CIL_INFO, "Failed to write booleanif content to file, rc: %d\n", rc);
			return rc;
		}
	}
	fprintf(file_arr[file_index], "}\n");

	if (false_node != NULL) {
		fprintf(file_arr[file_index], "else {\n");
		rc = cil_tree_walk(false_node, __cil_booleanif_node_helper, __cil_booleanif_last_child_helper, NULL, &extra_args);
		if (rc != SEPOL_OK) {
			cil_log(CIL_INFO, "Failed to write booleanif false content to file, rc: %d\n", rc);
			return rc;
		}
		fprintf(file_arr[file_index], "}\n");
	}

	return SEPOL_OK;
}

int cil_name_to_policy(FILE **file_arr, struct cil_tree_node *current) 
{
	uint32_t flavor = current->flavor;
	int rc = SEPOL_ERR;

	switch(flavor) {
	case CIL_TYPEATTRIBUTE:
		fprintf(file_arr[TYPEATTRTYPES], "attribute %s;\n", ((struct cil_symtab_datum*)current->data)->name);
		break;
	case CIL_TYPE:
		fprintf(file_arr[TYPEATTRTYPES], "type %s;\n", ((struct cil_symtab_datum*)current->data)->name);
		break;
	case CIL_TYPEALIAS: {
		struct cil_alias *alias = current->data;
		fprintf(file_arr[ALIASES], "typealias %s alias %s;\n", ((struct cil_symtab_datum*)alias->actual)->name, ((struct cil_symtab_datum*)current->data)->name);
		break;
	}
	case CIL_TYPEBOUNDS: {
		struct cil_bounds *bnds = current->data;
		fprintf(file_arr[ALLOWS], "typebounds %s %s;\n", bnds->parent_str, bnds->child_str);
		break;
	}
	case CIL_TYPEPERMISSIVE: {
		struct cil_typepermissive *typeperm = (struct cil_typepermissive*)current->data;
		fprintf(file_arr[TYPEATTRTYPES], "permissive %s;\n", ((struct cil_symtab_datum*)typeperm->type)->name);
		break;
	}
	case CIL_ROLE:
		fprintf(file_arr[TYPEATTRTYPES], "role %s;\n", ((struct cil_symtab_datum*)current->data)->name);
		break;
	case CIL_BOOL: {
		const char *boolean = ((struct cil_bool*)current->data)->value ? "true" : "false";
		fprintf(file_arr[TYPEATTRTYPES], "bool %s %s;\n", ((struct cil_symtab_datum*)current->data)->name, boolean);
		break;
	}
	case CIL_COMMON:
		fprintf(file_arr[COMMONS], "common %s", ((struct cil_symtab_datum*)current->data)->name);

		if (current->cl_head != NULL) {
			current = current->cl_head;
			fprintf(file_arr[COMMONS], " {");
		} else {
			cil_log(CIL_INFO, "No permissions given\n");
			return SEPOL_ERR;
		}

		while (current != NULL) {
			if (current->flavor == CIL_PERM) {
				fprintf(file_arr[COMMONS], "%s ", ((struct cil_symtab_datum*)current->data)->name);
			} else {
				cil_log(CIL_INFO, "Improper data type found in common permissions: %d\n", current->flavor);
				return SEPOL_ERR;
			}
			current = current->next;
		}
		fprintf(file_arr[COMMONS], "}\n");

		return SEPOL_DONE;
	case CIL_AVRULE: {
		struct cil_avrule *avrule = (struct cil_avrule*)current->data;
		rc = cil_avrule_to_policy(file_arr, ALLOWS, avrule);
		if (rc != SEPOL_OK) {
			cil_log(CIL_INFO, "Failed to write avrule to policy\n");
			return rc;
		}
		break;
	}
	case CIL_TYPE_RULE: {
		struct cil_type_rule *rule = (struct cil_type_rule*)current->data;
		rc = cil_typerule_to_policy(file_arr, ALLOWS, rule);
		if (rc != SEPOL_OK) {
			cil_log(CIL_INFO, "Failed to write type rule to policy\n");
			return rc;
		}
		break;
	}
	case CIL_NAMETYPETRANSITION: {
		struct cil_nametypetransition *nametypetrans = (struct cil_nametypetransition*)current->data;
		rc = cil_nametypetransition_to_policy(file_arr, ALLOWS, nametypetrans);
		if (rc != SEPOL_OK) {
			cil_log(CIL_INFO, "Failed to write nametypetransition to policy\n");
			return rc;
		}
	}
	case CIL_ROLETRANSITION: {
		struct cil_roletransition *roletrans = (struct cil_roletransition*)current->data;
		char *src_str = ((struct cil_symtab_datum*)roletrans->src)->name;
		char *tgt_str = ((struct cil_symtab_datum*)roletrans->tgt)->name;
		char *obj_str = ((struct cil_symtab_datum*)roletrans->obj)->name;
		char *result_str = ((struct cil_symtab_datum*)roletrans->result)->name;
		
		fprintf(file_arr[ALLOWS], "role_transition %s %s:%s %s;\n", src_str, tgt_str, obj_str, result_str);
		break;
	}
	case CIL_ROLEALLOW: {
		struct cil_roleallow *roleallow = (struct cil_roleallow*)current->data;
		char *src_str = ((struct cil_symtab_datum*)roleallow->src)->name;
		char *tgt_str = ((struct cil_symtab_datum*)roleallow->tgt)->name;

		fprintf(file_arr[ALLOWS], "roleallow %s %s;\n", src_str, tgt_str);
		break;
	}
	case CIL_ROLETYPE: {
		struct cil_roletype *roletype = (struct cil_roletype*)current->data;
		char *role_str = ((struct cil_symtab_datum*)roletype->role)->name;
		char *type_str = ((struct cil_symtab_datum*)roletype->type)->name;

		fprintf(file_arr[ALIASES], "role %s types %s\n", role_str, type_str);
		break;
	}
	case CIL_LEVEL:
		fprintf(file_arr[LEVELS], "level ");
		cil_level_to_policy(file_arr, LEVELS, (struct cil_level*)current->data);
			fprintf(file_arr[LEVELS], ";\n");
			break;
	case CIL_CONSTRAIN:
		cil_constrain_to_policy(file_arr, CONSTRAINS, (struct cil_constrain*)current->data, flavor);
		break;
	case CIL_MLSCONSTRAIN:
		cil_constrain_to_policy(file_arr, CONSTRAINS, (struct cil_constrain*)current->data, flavor);
		break;
	case CIL_VALIDATETRANS: {
		struct cil_validatetrans *vt = current->data;
		fprintf(file_arr[CONSTRAINS], "validatetrans");
		fprintf(file_arr[CONSTRAINS], " %s ", ((struct cil_class*)vt->class)->datum.name);
		cil_expr_to_policy(file_arr, CONSTRAINS, vt->datum_expr);
		fprintf(file_arr[CONSTRAINS], ";\n");
		break;
	}
	case CIL_MLSVALIDATETRANS: {
		struct cil_validatetrans *vt = current->data;
		fprintf(file_arr[CONSTRAINS], "mlsvalidatetrans");
		fprintf(file_arr[CONSTRAINS], " %s " , ((struct cil_class*)vt->class)->datum.name);
		cil_expr_to_policy(file_arr, CONSTRAINS, vt->datum_expr);
		fprintf(file_arr[CONSTRAINS], ";\n");
		break;
	}
	case CIL_SID:
		fprintf(file_arr[ISIDS], "sid %s\n", ((struct cil_symtab_datum*)current->data)->name);
		break;
	case CIL_SIDCONTEXT: {
		struct cil_sidcontext *sidcon = (struct cil_sidcontext*)current->data;
		fprintf(file_arr[SIDS], "sid %s ", sidcon->sid_str);
		cil_context_to_policy(file_arr, SIDS, sidcon->context);
		fprintf(file_arr[SIDS], "\n");
		break;
	}
	case CIL_POLICYCAP:
		fprintf(file_arr[TYPEATTRTYPES], "policycap %s;\n", ((struct cil_symtab_datum*)current->data)->name);
		break;
	default:
		break;
	}

	return SEPOL_OK;
}

int __cil_gen_policy_node_helper(struct cil_tree_node *node, uint32_t *finished, void *extra_args)
{
	int rc = SEPOL_ERR;
	struct cil_args_genpolicy *args = NULL;
	struct cil_list *users = NULL;
	struct cil_list *sens = NULL;
	struct cil_list *cats = NULL;
	FILE **file_arr = NULL;

	if (extra_args == NULL) {
		return SEPOL_ERR;
	}

	*finished = CIL_TREE_SKIP_NOTHING;

	args = extra_args;
	users = args->users;
	sens = args->sens;
	cats = args->cats;
	file_arr = args->file_arr;

	if (node->cl_head != NULL) {
		if (node->flavor == CIL_MACRO) {
			*finished = CIL_TREE_SKIP_HEAD;
			return SEPOL_OK;
		}

		if (node->flavor == CIL_BOOLEANIF) {
			rc = cil_booleanif_to_policy(file_arr, CONDS, node);
			if (rc != SEPOL_OK) {
				cil_log(CIL_INFO, "Failed to write booleanif contents to file\n");
				return rc;
			}
			*finished = CIL_TREE_SKIP_HEAD;
			return SEPOL_OK;
		}

		if (node->flavor == CIL_BLOCK && ((struct cil_block*)node->data)->is_abstract == CIL_TRUE) {
			*finished = CIL_TREE_SKIP_HEAD;
			return SEPOL_OK;
		}

		if (node->flavor != CIL_ROOT) {
			rc = cil_name_to_policy(file_arr, node);
			if (rc != SEPOL_OK && rc != SEPOL_DONE) {
				cil_log(CIL_ERR, "Error converting node to policy %d\n", node->flavor);
				return SEPOL_ERR;
			}
		}
	} else {
		switch (node->flavor) {
		case CIL_USER:
			cil_multimap_insert(users, node->data, NULL, CIL_USERROLE, CIL_NONE);
			break;
		case CIL_CATALIAS: {
			struct cil_alias *alias = node->data;
			struct cil_symtab_datum *datum = alias->actual;
			cil_multimap_insert(cats, datum, node->data, CIL_CAT, CIL_CATALIAS);
		}
			break;
		case CIL_SENSALIAS: {
			struct cil_alias *alias = node->data;
			struct cil_symtab_datum *datum = alias->actual;
			cil_multimap_insert(sens, datum, node->data, CIL_SENS, CIL_SENSALIAS);
		}
			break;
		default:
			rc = cil_name_to_policy(file_arr, node);
			if (rc != SEPOL_OK && rc != SEPOL_DONE) {
				cil_log(CIL_ERR, "Error converting node to policy %d\n", rc);
				return SEPOL_ERR;
			}
			break;
		}
	}

	return SEPOL_OK;
}

int cil_gen_policy(struct cil_db *db)
{
	struct cil_tree_node *curr = db->ast->root;
	struct cil_list_item *item;
	int rc = SEPOL_ERR;
	FILE *policy_file;
	FILE **file_arr = cil_malloc(sizeof(FILE*) * NUM_POLICY_FILES);
	char *file_path_arr[NUM_POLICY_FILES];
	char temp[32];

	struct cil_list *users = NULL;
	struct cil_list *cats = NULL;
	struct cil_list *sens = NULL;
	struct cil_args_genpolicy extra_args;

	cil_list_init(&users, CIL_LIST_ITEM);
	cil_list_init(&cats, CIL_LIST_ITEM);
	cil_list_init(&sens, CIL_LIST_ITEM);

	strcpy(temp, "/tmp/cil_classdecl-XXXXXX");
	file_arr[CLASS_DECL] = fdopen(mkstemp(temp), "w+");
	file_path_arr[CLASS_DECL] = cil_strpool_add(temp);

	strcpy(temp, "/tmp/cil_isids-XXXXXX");
	file_arr[ISIDS] = fdopen(mkstemp(temp), "w+");
	file_path_arr[ISIDS] = cil_strpool_add(temp);

	strcpy(temp,"/tmp/cil_common-XXXXXX");
	file_arr[COMMONS] = fdopen(mkstemp(temp), "w+");
	file_path_arr[COMMONS] = cil_strpool_add(temp);
	
	strcpy(temp, "/tmp/cil_class-XXXXXX");
	file_arr[CLASSES] = fdopen(mkstemp(temp), "w+");
	file_path_arr[CLASSES] = cil_strpool_add(temp);

	strcpy(temp, "/tmp/cil_interf-XXXXXX");
	file_arr[INTERFACES] = fdopen(mkstemp(temp), "w+");
	file_path_arr[INTERFACES] = cil_strpool_add(temp);

	strcpy(temp, "/tmp/cil_sens-XXXXXX");
	file_arr[SENS] = fdopen(mkstemp(temp), "w+");
	file_path_arr[SENS] = cil_strpool_add(temp);

	strcpy(temp, "/tmp/cil_cats-XXXXXX");
	file_arr[CATS] = fdopen(mkstemp(temp), "w+");
	file_path_arr[CATS] = cil_strpool_add(temp);

	strcpy(temp, "/tmp/cil_levels-XXXXXX");
	file_arr[LEVELS] = fdopen(mkstemp(temp), "w+");
	file_path_arr[LEVELS] = cil_strpool_add(temp);

	strcpy(temp, "/tmp/cil_mlscon-XXXXXX");
	file_arr[CONSTRAINS] = fdopen(mkstemp(temp), "w+");
	file_path_arr[CONSTRAINS] = cil_strpool_add(temp);

	strcpy(temp, "/tmp/cil_attrtypes-XXXXXX");
	file_arr[TYPEATTRTYPES] = fdopen(mkstemp(temp), "w+");
	file_path_arr[TYPEATTRTYPES] = cil_strpool_add(temp);
	
	strcpy(temp, "/tmp/cil_aliases-XXXXXX");
	file_arr[ALIASES] = fdopen(mkstemp(temp), "w+");
	file_path_arr[ALIASES] = cil_strpool_add(temp);
	
	strcpy(temp, "/tmp/cil_allows-XXXXXX");
	file_arr[ALLOWS] = fdopen(mkstemp(temp), "w+");
	file_path_arr[ALLOWS] = cil_strpool_add(temp);
	
	strcpy(temp, "/tmp/cil_conds-XXXXXX");
	file_arr[CONDS] = fdopen(mkstemp(temp), "w+");
	file_path_arr[CONDS] = cil_strpool_add(temp);
	
	strcpy(temp, "/tmp/cil_userroles-XXXXXX");
	file_arr[USERROLES] = fdopen(mkstemp(temp), "w+");
	file_path_arr[USERROLES] = cil_strpool_add(temp);

	strcpy(temp, "/tmp/cil_sids-XXXXXX");
	file_arr[SIDS] = fdopen(mkstemp(temp), "w+");
	file_path_arr[SIDS] = cil_strpool_add(temp);

	strcpy(temp, "/tmp/cil_netifcons-XXXXXX");
	file_arr[NETIFCONS] = fdopen(mkstemp(temp), "w+");
	file_path_arr[NETIFCONS] = cil_strpool_add(temp);

	policy_file = fopen("policy.conf", "w+");

	cil_list_for_each(item, db->sidorder) {
		fprintf(file_arr[ISIDS], "sid %s ", ((struct cil_sid*)item->data)->datum.name);
	}

	cil_list_for_each(item, db->classorder) {
		struct cil_class *class = item->data;
		struct cil_tree_node *node = class->datum.nodes->head->data;

		fprintf(file_arr[CLASS_DECL], "class %s\n", class->datum.name);

		fprintf(file_arr[CLASSES], "class %s ", class->datum.name);
		if (class->common != NULL) {
			fprintf(file_arr[CLASSES], "inherits %s ", class->common->datum.name);
		}
		if (node->cl_head != NULL) {
			struct cil_tree_node *curr_perm = node->cl_head;
			fprintf(file_arr[CLASSES], "{ ");
			while (curr_perm != NULL) {
				fprintf(file_arr[CLASSES], "%s ", ((struct cil_symtab_datum*)curr_perm->data)->name);
				curr_perm = curr_perm->next;
			}
			fprintf(file_arr[CLASSES], "}");
		}
		fprintf(file_arr[CLASSES], "\n");
	}

	if (db->catorder->head != NULL) {
		cil_list_for_each(item, db->catorder) {
			cil_multimap_insert(cats, item->data, NULL, CIL_CAT, 0);
		}
	}

	if (db->sensitivityorder->head != NULL) {
		fprintf(file_arr[SENS], "sensitivityorder { ");
		cil_list_for_each(item, db->sensitivityorder) {
			fprintf(file_arr[SENS], "%s ", ((struct cil_sens*)item->data)->datum.name);
		}
		fprintf(file_arr[SENS], "};\n");
	}

	extra_args.users = users;
	extra_args.sens = sens;
	extra_args.cats = cats;
	extra_args.file_arr= file_arr;

	rc = cil_tree_walk(curr, __cil_gen_policy_node_helper, NULL, NULL, &extra_args);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Error walking tree\n");
		return rc;
	}

	rc = cil_netifcon_to_policy(file_arr, db->netifcon);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Error creating policy.conf\n");
		return rc;
	}
	
	rc = cil_genfscon_to_policy(file_arr, db->genfscon);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Error creating policy.conf\n");
		return rc;
	}

	rc = cil_portcon_to_policy(file_arr, db->portcon);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Error creating policy.conf\n");
		return rc;
	}

	rc = cil_nodecon_to_policy(file_arr, db->nodecon);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Error creating policy.conf\n");
		return rc;
	}

	rc = cil_fsuse_to_policy(file_arr, db->fsuse);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Error creating policy.conf\n");
		return rc;
	}

	rc = cil_pirqcon_to_policy(file_arr, db->pirqcon);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Error creating policy.conf\n");
		return rc;
	}

	rc = cil_iomemcon_to_policy(file_arr, db->iomemcon);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Error creating policy.conf\n");
		return rc;
	}

	rc = cil_ioportcon_to_policy(file_arr, db->ioportcon);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Error creating policy.conf\n");
		return rc;
	}

	rc = cil_pcidevicecon_to_policy(file_arr, db->pcidevicecon);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Error creating policy.conf\n");
		return rc;
	}

	rc = cil_userrole_to_policy(file_arr, users);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Error creating policy.conf\n");
		return SEPOL_ERR;
	}

	rc = cil_sens_to_policy(file_arr, sens);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Error creating policy.conf\n");
		return SEPOL_ERR;
	}

	rc = cil_cat_to_policy(file_arr, cats);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Error creating policy.conf\n");
		return SEPOL_ERR;
	}

	rc = cil_combine_policy(file_arr, policy_file);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Error creating policy.conf\n");
		return SEPOL_ERR;
	}

	// Remove temp files
	int i;
	for (i=0; i<NUM_POLICY_FILES; i++) {
		rc = fclose(file_arr[i]);
		if (rc != 0) {
			cil_log(CIL_ERR, "Error closing temporary file\n");
			return SEPOL_ERR;
		}
		rc = unlink(file_path_arr[i]);
		if (rc != 0) {
			cil_log(CIL_ERR, "Error unlinking temporary files\n");
			return SEPOL_ERR;
		}
	}

	rc = fclose(policy_file);
	if (rc != 0) {
		cil_log(CIL_ERR, "Error closing policy.conf\n");
		return SEPOL_ERR;
	}
	free(file_arr);
	
	cil_list_destroy(&users, CIL_FALSE);
	cil_list_destroy(&cats, CIL_FALSE);
	cil_list_destroy(&sens, CIL_FALSE);
	
	return SEPOL_OK;
}
