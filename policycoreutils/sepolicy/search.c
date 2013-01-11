// Author: Thomas Liu <tliu@redhat.com>

/**
 *  @file
 *  Python bindings used to search TE rules.
 *
 *  @author Thomas Liu  <tliu@redhat.com>
 *  @author Dan Walsh  <dwalsh@redhat.com>
 *  Copyright (C) 2012-2013 Red Hat, inc
 *
 *  Sections copied from sesearch.c in setools package
 *  @author Frank Mayer  mayerf@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Paul Rosenfeld  prosenfeld@tresys.com
 *  Copyright (C) 2003-2008 Tresys Technology, LLC
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

/**
 * This is a modified version of sesearch to be used as part of a sepython library for
 * Python bindings.
 */

#include "common.h"
#include "policy.h"

/* libapol */
#include <apol/policy-query.h>
#include <apol/render.h>
#include <apol/util.h>
#include <apol/vector.h>

/* libqpol*/
#include <qpol/policy.h>
#include <qpol/policy_extend.h>
#include <qpol/syn_rule_query.h>
#include <qpol/util.h>

/* other */
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <getopt.h>
#include <string.h>
#include <stdbool.h>

#define COPYRIGHT_INFO "Copyright (C) 2012 Red Hat, Inc, Tresys Technology, LLC"

enum opt_values
{
	RULE_NEVERALLOW = 256, RULE_AUDIT, RULE_AUDITALLOW, RULE_DONTAUDIT,
	RULE_ROLE_ALLOW, RULE_ROLE_TRANS, RULE_RANGE_TRANS, RULE_ALL,
	EXPR_ROLE_SOURCE, EXPR_ROLE_TARGET
};

;

typedef struct options
{
	char *src_name;
	char *tgt_name;
	char *src_role_name;
	char *tgt_role_name;
	char *class_name;
	char *permlist;
	char *bool_name;
	apol_vector_t *class_vector;
	bool all;
	bool lineno;
	bool semantic;
	bool indirect;
	bool allow;
	bool nallow;
	bool auditallow;
	bool dontaudit;
	bool type;
	bool rtrans;
	bool role_allow;
	bool role_trans;
	bool useregex;
	bool show_cond;
	apol_vector_t *perm_vector;
} options_t;

static int py_tuple_insert_obj(PyObject *tuple, int pos, PyObject *obj)
{
	int rt;
	if (!obj) return -1;
	rt = PyTuple_SetItem(tuple, pos, obj);
	return rt;
}

static int perform_ra_query(const apol_policy_t * policy, const options_t * opt, apol_vector_t ** v)
{
	apol_role_allow_query_t *raq = NULL;
	int error = 0;

	if (!policy || !opt || !v) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	if (!opt->role_allow && !opt->all) {
		*v = NULL;
		return 0;	       /* no search to do */
	}

	raq = apol_role_allow_query_create();
	if (!raq) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	apol_role_allow_query_set_regex(policy, raq, opt->useregex);
	if (opt->src_role_name) {
		if (apol_role_allow_query_set_source(policy, raq, opt->src_role_name)) {
			error = errno;
			goto err;
		}
	}
	if (opt->tgt_role_name)
		if (apol_role_allow_query_set_target(policy, raq, opt->tgt_role_name)) {
			error = errno;
			goto err;
		}

	if (apol_role_allow_get_by_query(policy, raq, v)) {
		error = errno;
		goto err;
	}
	apol_role_allow_query_destroy(&raq);
	return 0;

      err:
	apol_vector_destroy(v);
	apol_role_allow_query_destroy(&raq);
	ERR(policy, "%s", strerror(error));
	errno = error;
	return -1;
}

static PyObject* get_ra_results(const apol_policy_t * policy, const apol_vector_t * v, PyObject *output)
{
	size_t i, num_rules = 0;
	qpol_policy_t *q;
	const qpol_role_allow_t *rule = NULL;
	const char *tmp;
	PyObject *obj, *dict=NULL;
	const qpol_role_t *role = NULL;
	int error = 0;
	errno = EINVAL;
	int rt;

	if (!policy || !v) {
		errno = EINVAL;
		goto err;
	}

	if (!(num_rules = apol_vector_get_size(v)))
		return NULL;

	q = apol_policy_get_qpol(policy);

	for (i = 0; i < num_rules; i++) {
		dict = PyDict_New();
		if (!dict) goto err;
		if (!(rule = apol_vector_get_element(v, i)))
			goto err;

		if (qpol_role_allow_get_source_role(q, rule, &role)) {
			goto err;
		}
		if (qpol_role_get_name(q, role, &tmp)) {
			goto err;
		}
		obj = PyString_FromString(tmp);
		if (py_insert_obj(dict, "source", obj))
			goto err;

		if (qpol_role_allow_get_target_role(q, rule, &role)) {
			goto err;
		}
		if (qpol_role_get_name(q, role, &tmp)) {
			goto err;
		}
		obj = PyString_FromString(tmp);
		if (py_insert_obj(dict, "target", obj))
			goto err;

		rt = py_append_obj(output, dict);
		if (rt) goto err;
		py_decref(dict); dict=NULL;
	}
	goto cleanup;
err:
	error = errno;
	PyErr_SetString(PyExc_RuntimeError,strerror(error));
	py_decref(dict);

cleanup:
	errno = error;
	return output;
}

static int perform_te_query(const apol_policy_t * policy, const options_t * opt, apol_vector_t ** v)
{
	apol_terule_query_t *teq = NULL;
	unsigned int rules = 0;
	int error = 0;
	size_t i;

	if (!policy || !opt || !v) {
		PyErr_SetString(PyExc_RuntimeError,strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	if (opt->all || opt->type) {
		rules = (QPOL_RULE_TYPE_TRANS | QPOL_RULE_TYPE_CHANGE | QPOL_RULE_TYPE_MEMBER);
	} else {
		*v = NULL;
		return 0;	       /* no search to do */
	}

	teq = apol_terule_query_create();
	if (!teq) {
		PyErr_SetString(PyExc_RuntimeError,strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	apol_terule_query_set_rules(policy, teq, rules);
	apol_terule_query_set_regex(policy, teq, opt->useregex);

	if (opt->src_name)
		apol_terule_query_set_source(policy, teq, opt->src_name, opt->indirect);
	if (opt->tgt_name)
		apol_terule_query_set_target(policy, teq, opt->tgt_name, opt->indirect);
	if (opt->bool_name)
		apol_terule_query_set_bool(policy, teq, opt->bool_name);
	if (opt->class_name) {
		if (opt->class_vector == NULL) {
			if (apol_terule_query_append_class(policy, teq, opt->class_name)) {
				error = errno;
				goto err;
			}
		} else {
			for (i = 0; i < apol_vector_get_size(opt->class_vector); ++i) {
				char *class_name;
				class_name = apol_vector_get_element(opt->class_vector, i);
				if (!class_name)
					continue;
				if (apol_terule_query_append_class(policy, teq, class_name)) {
					error = errno;
					goto err;
				}
			}
		}
	}

	if (!(opt->semantic) && qpol_policy_has_capability(apol_policy_get_qpol(policy), QPOL_CAP_SYN_RULES)) {
		if (apol_syn_terule_get_by_query(policy, teq, v)) {
			goto err;
		}
	} else {
		if (apol_terule_get_by_query(policy, teq, v)) {
			goto err;
		}
	}

	apol_terule_query_destroy(&teq);
	return 0;

err:
	error = errno;
	PyErr_SetString(PyExc_RuntimeError,strerror(error));
	apol_vector_destroy(v);
	apol_terule_query_destroy(&teq);
	errno = error;
	return -1;
}

static PyObject* get_bool(const qpol_policy_t *q, const qpol_cond_t * cond, int enabled)
{
	qpol_iterator_t *iter = NULL;
	qpol_cond_expr_node_t *expr = NULL;
	char *tmp = NULL;
	const char *bool_name = NULL;
	int error = 0;
	uint32_t expr_type = 0;
	qpol_bool_t *cond_bool = NULL;
	PyObject *obj, *tuple = NULL;
	PyObject *boollist = NULL;

	if (!q || !cond) {
		errno = EINVAL;
		return NULL;
	}
	if (qpol_cond_get_expr_node_iter(q, cond, &iter) < 0) {
		goto err;
	}

	boollist = PyList_New(0);
	if (! boollist) goto err;

	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **)&expr)) {
			goto err;
		}
		if (qpol_cond_expr_node_get_expr_type(q, expr, &expr_type)) {
			goto err;
		}
		if (expr_type != QPOL_COND_EXPR_BOOL) {
			obj = PyString_FromString(apol_cond_expr_type_to_str(expr_type));
			if (!obj) goto err;
			if (py_append_obj(boollist, obj))
				goto err;
		} else {
			tuple = PyTuple_New(2);
			if (!tuple) goto err;

			if (qpol_cond_expr_node_get_bool(q, expr, &cond_bool)) {
				goto err;
			}
			if (qpol_bool_get_name(q, cond_bool, &bool_name)) {
				goto err;
			}
			obj = PyString_FromString(bool_name);
			if (py_tuple_insert_obj(tuple, 0, obj))
				goto err;
			obj = PyBool_FromLong(enabled);
			if (py_tuple_insert_obj(tuple, 1, obj))
				goto err;
			if (py_append_obj(boollist, tuple)) 
				goto err;
			tuple=NULL;
		}
	}

	qpol_iterator_destroy(&iter);
	return boollist;

      err:
	error = errno;
	qpol_iterator_destroy(&iter);
	py_decref(tuple);
	py_decref(boollist);
	free(tmp);
	errno = error;
	return NULL;
}

static PyObject* get_te_results(const apol_policy_t * policy, const apol_vector_t * v, PyObject *output)
{
	int error = 0;
	int rt = 0;
	PyObject *obj, *dict=NULL, *tuple = NULL;
	qpol_policy_t *q;
	uint32_t rule_type = 0;
	const qpol_type_t *type;
	size_t i, num_rules = 0;
	const qpol_terule_t *rule = NULL;
	char *tmp = NULL, *rule_str = NULL, *expr = NULL;
	const qpol_cond_t *cond = NULL;
	uint32_t enabled = 0;
	const char *tmp_name;
	const qpol_class_t *obj_class = NULL;

	if (!policy || !v) {
		errno = EINVAL;
		goto err;
	}

	if (!(num_rules = apol_vector_get_size(v)))
		return NULL;

	q = apol_policy_get_qpol(policy);

	for (i = 0; i < num_rules; i++) {
		dict = PyDict_New();
		if (!dict) goto err;
		if (!(rule = apol_vector_get_element(v, i)))
			goto err;
		if (qpol_terule_get_cond(q, rule, &cond))
			goto err;
		if (qpol_terule_get_is_enabled(q, rule, &enabled))
			goto err;

		if (cond) {
			obj = get_bool(q, cond, enabled);
			if (!obj) goto err;
			rt = PyDict_SetItemString(dict, "boolean", obj);
			py_decref(obj);
		}

		if (qpol_terule_get_rule_type(q, rule, &rule_type))
			goto err;

		if (!(rule_type &= (QPOL_RULE_TYPE_TRANS | QPOL_RULE_TYPE_CHANGE | QPOL_RULE_TYPE_MEMBER))) {
			PyErr_SetString(PyExc_RuntimeError,"Invalid TE rule type");
			errno = EINVAL;
			goto err;
		}
		if (!(tmp_name = apol_rule_type_to_str(rule_type))) {
			PyErr_SetString(PyExc_RuntimeError, "Could not get TE rule type's string");
			errno = EINVAL;
			goto err;
		}

		if (py_insert_string(dict, "type", tmp_name))
			goto err;

		if (qpol_terule_get_source_type(q, rule, &type))
			goto err;
		if (qpol_type_get_name(q, type, &tmp_name))
			goto err;
		if (py_insert_string(dict, "source", tmp_name))
			goto err;

		if (qpol_terule_get_target_type(q, rule, &type))
			goto err;
		if (qpol_type_get_name(q, type, &tmp_name))
			goto err;
		if (py_insert_string(dict, "target", tmp_name))
			goto err;

		if (qpol_terule_get_object_class(q, rule, &obj_class))
			goto err;
		if (qpol_class_get_name(q, obj_class, &tmp_name))
			goto err;
		if (py_insert_string(dict, "class", tmp_name))
			goto err;

		if (qpol_terule_get_default_type(q, rule, &type))
			goto err;
		if (qpol_type_get_name(q, type, &tmp_name))
			goto err;
		if (py_insert_string(dict, "transtype", tmp_name))
			goto err;

		rt = py_append_obj(output, dict);
		dict = NULL;
		if(rt) goto err;

		free(rule_str);	rule_str = NULL;
		free(expr); expr = NULL;
	}
	goto cleanup;

err:
	error = errno;
	py_decref(dict);
	py_decref(tuple);
	PyErr_SetString(PyExc_RuntimeError,strerror(error));
cleanup:
	free(tmp);
	free(rule_str);
	free(expr);
	errno = error;
	return output;
}

static int perform_ft_query(const apol_policy_t * policy, const options_t * opt, apol_vector_t ** v)
{
	apol_filename_trans_query_t *ftq = NULL;
	size_t i;
	int error = 0;

	if (!policy || !opt || !v) {
		PyErr_SetString(PyExc_RuntimeError,strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	if (!opt->type && !opt->all) {
		*v = NULL;
		return 0;	       /* no search to do */
	}

	ftq = apol_filename_trans_query_create();
	if (!ftq) {
		PyErr_SetString(PyExc_RuntimeError,strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	apol_filename_trans_query_set_regex(policy, ftq, opt->useregex);
	if (opt->src_name) {
		if (apol_filename_trans_query_set_source(policy, ftq, opt->src_name, opt->indirect)) {
			goto err;
		}
	}

	if (opt->tgt_name) {
		if (apol_filename_trans_query_set_target(policy, ftq, opt->tgt_name, opt->indirect)) {
			goto err;
		}
	}
	if (opt->class_name) {
		if (opt->class_vector == NULL) {
			if (apol_filename_trans_query_append_class(policy, ftq, opt->class_name)) {
				goto err;
			}
		} else {
			for (i = 0; i < apol_vector_get_size(opt->class_vector); ++i) {
				char *class_name;
				class_name = apol_vector_get_element(opt->class_vector, i);
				if (!class_name)
					continue;
				if (apol_filename_trans_query_append_class(policy, ftq, class_name)) {
					goto err;
				}
			}
		}
	}

	if (apol_filename_trans_get_by_query(policy, ftq, v))
		goto err;

	apol_filename_trans_query_destroy(&ftq);
	return 0;

err:
	error = errno;
	PyErr_SetString(PyExc_RuntimeError,strerror(errno));
	apol_vector_destroy(v);
	apol_filename_trans_query_destroy(&ftq);
	errno = error;
	return -1;
}

static PyObject* get_ft_results(const apol_policy_t * policy, const apol_vector_t * v, PyObject *list)
{
	PyObject *dict = NULL;
	size_t i, num_filename_trans = 0;
	const char *tmp_name;
	int error = 0;
	int rt;
	const qpol_filename_trans_t *filename_trans = NULL;
	const qpol_class_t *obj_class = NULL;
	char *tmp = NULL, *filename_trans_str = NULL, *expr = NULL;
	qpol_policy_t *q;
	const qpol_type_t *type = NULL;

	if (!policy || !v) {
		errno = EINVAL;
		goto err;
	}

	if (!(num_filename_trans = apol_vector_get_size(v)))
		return NULL;

	q = apol_policy_get_qpol(policy);

	for (i = 0; i < num_filename_trans; i++) {
		if (!(filename_trans = apol_vector_get_element(v, i)))
			goto err;

		dict = PyDict_New();
		if (!dict) goto err;

		if (py_insert_string(dict, "type", "type_transition"))
			goto err;

		/* source type */
		if (qpol_filename_trans_get_source_type(q, filename_trans, &type)) {
			goto err;
		}
		if (qpol_type_get_name(q, type, &tmp_name)) {
			goto err;
		}

		if (py_insert_string(dict, "source", tmp_name))
			goto err;

		if (qpol_filename_trans_get_target_type(q, filename_trans, &type))
			goto err;

		if (qpol_type_get_name(q, type, &tmp_name))
			goto err;

		if (py_insert_string(dict, "target", tmp_name))
			goto err;

		if (qpol_filename_trans_get_object_class(q, filename_trans, &obj_class))
			goto err;

		if (qpol_class_get_name(q, obj_class, &tmp_name))
			goto err;

		if (py_insert_string(dict, "class", tmp_name))
			goto err;

		if (qpol_filename_trans_get_default_type(q, filename_trans, &type))
			goto err;
		if (qpol_type_get_name(q, type, &tmp_name))
			goto err;
		if (py_insert_string(dict, "transtype", tmp_name))
			goto err;

		if (! qpol_filename_trans_get_filename(q, filename_trans, &tmp_name)) {
			if (py_insert_string(dict, "filename", tmp_name))
				goto err;
		}

		rt = py_append_obj(list, dict);
		dict = NULL;
		if (rt) goto err;

		free(filename_trans_str); filename_trans_str = NULL;
		free(expr); expr = NULL;
	}
	goto cleanup;

err:
	error = errno;
	PyErr_SetString(PyExc_RuntimeError,strerror(errno));
	py_decref(dict);
cleanup:
	free(tmp);
	free(filename_trans_str);
	free(expr);
	errno = error;
	return list;
}

static int perform_av_query(const apol_policy_t * policy, const options_t * opt, apol_vector_t ** v)
{
	apol_avrule_query_t *avq = NULL;
	unsigned int rules = 0;
	int error = 0;
	char *tmp = NULL, *tok = NULL, *s = NULL;

	if (!policy || !opt || !v) {
		PyErr_SetString(PyExc_RuntimeError,strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	if (!opt->all && !opt->allow && !opt->nallow && !opt->auditallow && !opt->dontaudit) {
		*v = NULL;
		return 0;	       /* no search to do */
	}

	avq = apol_avrule_query_create();
	if (!avq) {
		PyErr_SetString(PyExc_RuntimeError,strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	if (opt->allow || opt->all)
		rules |= QPOL_RULE_ALLOW;
	if (opt->nallow || opt->all)	// Add this regardless of policy capabilities
		rules |= QPOL_RULE_NEVERALLOW;
	if (opt->auditallow || opt->all)
		rules |= QPOL_RULE_AUDITALLOW;
	if (opt->dontaudit || opt->all)
		rules |= QPOL_RULE_DONTAUDIT;
	if (rules != 0)	// Setting rules = 0 means you want all the rules
		apol_avrule_query_set_rules(policy, avq, rules);
	apol_avrule_query_set_regex(policy, avq, opt->useregex);
	if (opt->src_name)
		apol_avrule_query_set_source(policy, avq, opt->src_name, opt->indirect);
	if (opt->tgt_name)
		apol_avrule_query_set_target(policy, avq, opt->tgt_name, opt->indirect);
	if (opt->bool_name)
		apol_avrule_query_set_bool(policy, avq, opt->bool_name);
	if (opt->class_name) {
		if (opt->class_vector == NULL) {
			if (apol_avrule_query_append_class(policy, avq, opt->class_name)) {
				goto err;
			}
		} else {
			size_t i;
	    for (i = 0; i < apol_vector_get_size(opt->class_vector); ++i) {
				char *class_name;
				class_name = apol_vector_get_element(opt->class_vector, i);
				if (!class_name)
					continue;
				if (apol_avrule_query_append_class(policy, avq, class_name)) {
					goto err;
				}
			}
		}
	}

	if (opt->permlist) {
		tmp = strdup(opt->permlist);
		for (tok = strtok(tmp, ","); tok; tok = strtok(NULL, ",")) {
			if (apol_avrule_query_append_perm(policy, avq, tok)) {
				goto err;
			}
			if ((s = strdup(tok)) == NULL || apol_vector_append(opt->perm_vector, s) < 0) {
				goto err;
			}
			s = NULL;
		}
		free(tmp);
		tmp = NULL;
	}

	if (!(opt->semantic) && qpol_policy_has_capability(apol_policy_get_qpol(policy), QPOL_CAP_SYN_RULES)) {
		if (apol_syn_avrule_get_by_query(policy, avq, v)) {
			goto err;
		}
	} else {
		if (apol_avrule_get_by_query(policy, avq, v)) {
			goto err;
		}
	}

	apol_avrule_query_destroy(&avq);
	return 0;

err:
	error = errno;
	PyErr_SetString(PyExc_RuntimeError,strerror(error));
	apol_vector_destroy(v);
	apol_avrule_query_destroy(&avq);
	free(tmp);
	free(s);
	errno = error;
	return -1;
}

static PyObject* get_av_results(const apol_policy_t * policy, const apol_vector_t * v, PyObject *output)
{
	PyObject *obj, *dict=NULL;
	PyObject *permlist = NULL;
	PyObject *boollist = NULL;
	uint32_t rule_type = 0;
	int rt;
	int error = 0;
	qpol_policy_t *q;
	size_t i, num_rules = 0;
	const qpol_avrule_t *rule = NULL;
	char *tmp = NULL, *rule_str = NULL;
	qpol_cond_expr_node_t *expr = NULL;
	qpol_iterator_t *iter = NULL;
	const qpol_cond_t *cond = NULL;
	uint32_t enabled = 0;
	const qpol_type_t *type;
	const char *tmp_name;
	const qpol_class_t *obj_class = NULL;

	if (!policy || !v) {
		errno = EINVAL;
		goto err;
	}

	if (!(num_rules = apol_vector_get_size(v)))
		return NULL;

	q = apol_policy_get_qpol(policy);

	for (i = 0; i < num_rules; i++) {
		if (!(rule = apol_vector_get_element(v, i)))
			goto err;

		dict = PyDict_New();
		if (!dict) goto err;

		if (qpol_avrule_get_rule_type(q, rule, &rule_type))
			goto err;

		if (!(tmp_name = apol_rule_type_to_str(rule_type))) {
			PyErr_SetString(PyExc_RuntimeError, "Could not get TE rule type's string");
			errno = EINVAL;
			goto err;
		}

		if (py_insert_string(dict, "type", tmp_name))
			goto err;

		if (qpol_avrule_get_source_type(q, rule, &type)) {
			goto err;
		}

		if (qpol_type_get_name(q, type, &tmp_name)) {
			goto err;
		}

		if (py_insert_string(dict, "source", tmp_name))
			goto err;

		if (qpol_avrule_get_target_type(q, rule, &type)) {
			goto err;
		}
		if (qpol_type_get_name(q, type, &tmp_name)) {
			goto err;
		}

		if (py_insert_string(dict, "target", tmp_name))
			goto err;

		if (qpol_avrule_get_object_class(q, rule, &obj_class)) {
			goto err;
		}
		if (qpol_class_get_name(q, obj_class, &tmp_name)) {
			goto err;
		}

		if (py_insert_string(dict, "class", tmp_name))
			goto err;

		if (qpol_avrule_get_perm_iter(q, rule, &iter)) {
			goto err;
		}

		permlist = PyList_New(0);
		if (! permlist) goto err;

		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
			const char *perm_name = NULL;
			if (qpol_iterator_get_item(iter, (void **)&perm_name))
				goto err;
			if (py_append_string(permlist, perm_name))
				goto err;
		}

		rt = PyDict_SetItemString(dict, "permlist", permlist);
		py_decref(permlist); permlist=NULL;
		if (rt) goto err;

		if (qpol_avrule_get_cond(q, rule, &cond))
			goto err;
		if (qpol_avrule_get_is_enabled(q, rule, &enabled))
			goto err;

		obj = PyBool_FromLong(enabled);
		rt = PyDict_SetItemString(dict, "enabled", obj);
		py_decref(obj);

		if (cond) {
			obj = get_bool(q, cond, enabled);
			if (!obj) goto err;
			rt = PyDict_SetItemString(dict, "boolean", obj);
			py_decref(obj);
		}

		rt = py_append_obj(output, dict);
		py_decref(dict); dict=NULL;
		if (rt) goto err;

		free(rule_str);	rule_str = NULL;
		free(expr); expr = NULL;
	}
	goto cleanup;

err:
	error = errno;
	PyErr_SetString(PyExc_RuntimeError,strerror(errno));
	py_decref(dict);
	py_decref(permlist);
	py_decref(boollist);

cleanup:
	free(tmp);
	free(rule_str);
	free(expr);
	errno = error;
	return output;
}

PyObject* search(bool allow,
		 bool neverallow,
		 bool auditallow,
		 bool dontaudit,
		 bool transition,
		 bool role_allow,
		 const char *src_name,
		 const char *tgt_name,
		 const char *class_name,
		 const char *permlist
	)
{
	options_t cmd_opts;
	PyObject *output = NULL;
	apol_vector_t *v = NULL;

	memset(&cmd_opts, 0, sizeof(cmd_opts));
	cmd_opts.indirect = true;
	cmd_opts.show_cond = true;
	cmd_opts.allow = allow;
	cmd_opts.nallow = neverallow;
	cmd_opts.auditallow = auditallow;
	cmd_opts.dontaudit = dontaudit;
	cmd_opts.type = transition;
	cmd_opts.role_allow = role_allow;
	if (src_name)
		cmd_opts.src_name = strdup(src_name);
	if (tgt_name)
		cmd_opts.tgt_name = strdup(tgt_name);
	if (class_name)
		cmd_opts.class_name = strdup(class_name);
	if (permlist){
		cmd_opts.perm_vector = apol_vector_create(free);
		cmd_opts.permlist = strdup(permlist);
	}
	if (!cmd_opts.semantic && qpol_policy_has_capability(apol_policy_get_qpol(policy), QPOL_CAP_SYN_RULES)) {
		if (qpol_policy_build_syn_rule_table(apol_policy_get_qpol(policy))) {
			PyErr_SetString(PyExc_RuntimeError,"Query failed");
			goto cleanup;
		}
	}

	/* if syntactic rules are not available always do semantic search */
	if (!qpol_policy_has_capability(apol_policy_get_qpol(policy), QPOL_CAP_SYN_RULES)) {
		cmd_opts.semantic = 1;
	}

	/* supress line numbers if doing semantic search or not available */
	if (cmd_opts.semantic || !qpol_policy_has_capability(apol_policy_get_qpol(policy), QPOL_CAP_LINE_NUMBERS)) {
		cmd_opts.lineno = 0;
	}
	if (perform_av_query(policy, &cmd_opts, &v)) {
		goto cleanup;
	}
	output = PyList_New(0);
	if (!output)
		goto cleanup;

	if (v) {
		get_av_results(policy, v, output);
	}

	apol_vector_destroy(&v);
	if (perform_te_query(policy, &cmd_opts, &v)) {
		goto cleanup;
	}
	if (v) {
		get_te_results(policy, v, output);
	}

	if (cmd_opts.all || cmd_opts.type) {
		apol_vector_destroy(&v);
		if (perform_ft_query(policy, &cmd_opts, &v)) {
			goto cleanup;
		}

		if (v) {
			get_ft_results(policy, v, output);
		}
	}

	if (cmd_opts.all || cmd_opts.role_allow) {
		apol_vector_destroy(&v);
		if (perform_ra_query(policy, &cmd_opts, &v)) {
			goto cleanup;
		}

		if (v) {
			get_ra_results(policy, v, output);
		}
	}

	apol_vector_destroy(&v);

      cleanup:
	free(cmd_opts.src_name);
	free(cmd_opts.tgt_name);
	free(cmd_opts.class_name);
	free(cmd_opts.permlist);
	free(cmd_opts.bool_name);
	free(cmd_opts.src_role_name);
	free(cmd_opts.tgt_role_name);
	apol_vector_destroy(&cmd_opts.perm_vector);
	apol_vector_destroy(&cmd_opts.class_vector);

	if (output && PyList_GET_SIZE(output) == 0) {
		py_decref(output);
		return Py_None;
	}
	return output;
}

static int Dict_ContainsInt(PyObject *dict, const char *key){
    PyObject *item = PyDict_GetItemString(dict, key);
    if (item)
	return PyInt_AsLong(item);
    return false;
}

static const char *Dict_ContainsString(PyObject *dict, const char *key){
    PyObject *item = PyDict_GetItemString(dict, key);
    if (item)
	return PyString_AsString(item);
    return NULL;
}

PyObject *wrap_search(PyObject *UNUSED(self), PyObject *args){
    PyObject *dict;
    if (!PyArg_ParseTuple(args, "O", &dict))
	return NULL;
    int allow = Dict_ContainsInt(dict, "allow");
    int neverallow = Dict_ContainsInt(dict, "neverallow");
    int auditallow = Dict_ContainsInt(dict, "auditallow");
    int dontaudit = Dict_ContainsInt(dict, "dontaudit");
    int transition = Dict_ContainsInt(dict, "transition");
    int role_allow = Dict_ContainsInt(dict, "role_allow");

    if (!policy) {
	    PyErr_SetString(PyExc_RuntimeError,"Policy not loaded");
	    return NULL;
    }
    const char *src_name = Dict_ContainsString(dict, "source");
    const char *tgt_name = Dict_ContainsString(dict, "target");
    const char *class_name = Dict_ContainsString(dict, "class");
    const char *permlist = Dict_ContainsString(dict, "permlist");

    return search(allow, neverallow, auditallow, dontaudit, transition, role_allow, src_name, tgt_name, class_name, permlist);
}
