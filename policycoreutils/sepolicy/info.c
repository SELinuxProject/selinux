/**
 *  @file
 *  Command line tool to search TE rules.
 *
 *  @author Frank Mayer  mayerf@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Paul Rosenfeld  prosenfeld@tresys.com
 *  @author Thomas Liu  <tliu@redhat.com>
 *  @author Dan Walsh  <dwalsh@redhat.com>
 *
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
 * This is a modified version of seinfo to be used as part of a library for
 * Python bindings.
 */

#include "common.h"
#include "policy.h"

/* libapol */
#include <apol/policy-query.h>
#include <apol/render.h>
#include <apol/util.h>
#include <apol/vector.h>

/* libqpol */
#include <qpol/policy.h>
#include <qpol/util.h>

/* other */
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#define COPYRIGHT_INFO "Copyright (C) 2003-2007 Tresys Technology, LLC"

enum input
{
	TYPE, ATTRIBUTE, ROLE, USER, PORT, BOOLEAN, CLASS, SENS, CATS
};

static int py_insert_long(PyObject *dict, const char *name, int value)
{
	int rt;
	PyObject *obj = PyLong_FromLong(value);
	if (!obj) return -1;
	rt = PyDict_SetItemString(dict, name, obj);
	Py_DECREF(obj);
	return rt;
}

static int py_insert_bool(PyObject *dict, const char *name, int value)
{
	int rt;
	PyObject *obj = PyBool_FromLong(value);
	if (!obj) return -1;
	rt = PyDict_SetItemString(dict, name, obj);
	Py_DECREF(obj);
	return rt;
}

/**
 * Get a policy's MLS sensitivities.
 * If this function is given a name, it will attempt to
 * get statistics about a particular sensitivity; otherwise
 * the function gets statistics about all of the policy's
 * sensitivities.
 *
 * @param name Reference to a sensitivity's name; if NULL,
 * all sensitivities will be considered
 * @param policydb Reference to a policy
 *
 * @return 0 on success, < 0 on error.
 */
static PyObject* get_sens(const char *name, const apol_policy_t * policydb)
{
	PyObject *dict = NULL;
	int error = 0;
	int rt = 0;
	size_t i;
	char *tmp = NULL;
	const char *lvl_name = NULL;
	apol_level_query_t *query = NULL;
	apol_vector_t *v = NULL;
	const qpol_level_t *level = NULL;
	apol_mls_level_t *ap_mls_lvl = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);

	query = apol_level_query_create();
	if (!query)
		goto cleanup;
	if (apol_level_query_set_sens(policydb, query, name))
		goto cleanup;
	if (apol_level_get_by_query(policydb, query, &v))
		goto cleanup;

	dict = PyDict_New();
	if (!dict) goto err;
	for (i = 0; i < apol_vector_get_size(v); i++) {
		level = apol_vector_get_element(v, i);
		if (qpol_level_get_name(q, level, &lvl_name))
			goto err;
		ap_mls_lvl = (apol_mls_level_t *) apol_mls_level_create_from_qpol_level_datum(policydb, level);
		tmp = apol_mls_level_render(policydb, ap_mls_lvl);
		apol_mls_level_destroy(&ap_mls_lvl);
		if (!tmp)
			goto cleanup;
		if (py_insert_string(dict, lvl_name, tmp))
			goto err;
		free(tmp); tmp = NULL;
		if (rt) goto err;
	}

	if (name && !apol_vector_get_size(v)) {
		goto cleanup;
	}

	goto cleanup;
err:
	error = errno;
	PyErr_SetString(PyExc_RuntimeError,strerror(error));
	py_decref(dict); dict = NULL;
cleanup:
	free(tmp);
	apol_level_query_destroy(&query);
	apol_vector_destroy(&v);
	errno = error;
	return dict;
}

/**
 * Compare two qpol_cat_datum_t objects.
 * This function is meant to be passed to apol_vector_compare
 * as the callback for performing comparisons.
 *
 * @param datum1 Reference to a qpol_type_datum_t object
 * @param datum2 Reference to a qpol_type_datum_t object
 * @param data Reference to a policy
 * @return Greater than 0 if the first argument is less than the second argument,
 * less than 0 if the first argument is greater than the second argument,
 * 0 if the arguments are equal
 */
static int qpol_cat_datum_compare(const void *datum1, const void *datum2, void *data)
{
	const qpol_cat_t *cat_datum1 = NULL, *cat_datum2 = NULL;
	apol_policy_t *policydb = NULL;
	qpol_policy_t *q;
	uint32_t val1, val2;

	policydb = (apol_policy_t *) data;
	q = apol_policy_get_qpol(policydb);
	assert(policydb);

	if (!datum1 || !datum2)
		goto exit_err;
	cat_datum1 = datum1;
	cat_datum2 = datum2;

	if (qpol_cat_get_value(q, cat_datum1, &val1))
		goto exit_err;
	if (qpol_cat_get_value(q, cat_datum2, &val2))
		goto exit_err;

	return (val1 > val2) ? 1 : ((val1 == val2) ? 0 : -1);

      exit_err:
	assert(0);
	return 0;
}

/**
 * Compare two qpol_level_datum_t objects.
 * This function is meant to be passed to apol_vector_compare
 * as the callback for performing comparisons.
 *
 * @param datum1 Reference to a qpol_level_datum_t object
 * @param datum2 Reference to a qpol_level_datum_t object
 * @param data Reference to a policy
 * @return Greater than 0 if the first argument is less than the second argument,
 * less than 0 if the first argument is greater than the second argument,
 * 0 if the arguments are equal
 */
static int qpol_level_datum_compare(const void *datum1, const void *datum2, void *data)
{
	const qpol_level_t *lvl_datum1 = NULL, *lvl_datum2 = NULL;
	apol_policy_t *policydb = NULL;
	qpol_policy_t *q;
	uint32_t val1, val2;

	policydb = (apol_policy_t *) data;
	assert(policydb);
	q = apol_policy_get_qpol(policydb);

	if (!datum1 || !datum2)
		goto exit_err;
	lvl_datum1 = datum1;
	lvl_datum2 = datum2;

	if (qpol_level_get_value(q, lvl_datum1, &val1))
		goto exit_err;
	if (qpol_level_get_value(q, lvl_datum2, &val2))
		goto exit_err;

	return (val1 > val2) ? 1 : ((val1 == val2) ? 0 : -1);

      exit_err:
	assert(0);
	return 0;
}

/**
 * Gets a textual representation of a MLS category and
 * all of that category's sensitivies.
 *
 * @param type_datum Reference to sepol type_datum
 * @param policydb Reference to a policy
 */
static PyObject* get_cat_sens(const qpol_cat_t * cat_datum, const apol_policy_t * policydb)
{
	const char *cat_name, *lvl_name;
	apol_level_query_t *query = NULL;
	apol_vector_t *v = NULL;
	const qpol_level_t *lvl_datum = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);
	size_t i, n_sens = 0;
	int error = 0;
	PyObject *list = NULL;
	PyObject *dict = PyDict_New();
	if (!dict) goto err;
	if (!cat_datum || !policydb)
		goto err;

	/* get category name for apol query */
	if (qpol_cat_get_name(q, cat_datum, &cat_name))
		goto cleanup;

	query = apol_level_query_create();
	if (!query)
		goto err;
	if (apol_level_query_set_cat(policydb, query, cat_name))
		goto err;
	if (apol_level_get_by_query(policydb, query, &v))
		goto err;
	apol_vector_sort(v, &qpol_level_datum_compare, (void *)policydb);
	dict = PyDict_New();
	if (!dict) goto err;
	if (py_insert_string(dict, "name", cat_name))
		goto err;
	n_sens = apol_vector_get_size(v);
	list = PyList_New(0);
	if (!list) goto err;
	for (i = 0; i < n_sens; i++) {
		lvl_datum = (qpol_level_t *) apol_vector_get_element(v, i);
		if (!lvl_datum)
			goto err;
		if (qpol_level_get_name(q, lvl_datum, &lvl_name))
			goto err;
		if (py_append_string(list, lvl_name))
			goto err;
	}
	if (py_insert_obj(dict, "level", list))
		goto err;
	Py_DECREF(list);

	goto cleanup;
err:
	error = errno;
	PyErr_SetString(PyExc_RuntimeError,strerror(errno));
	py_decref(list); list = NULL;
	py_decref(dict); dict = NULL;
cleanup:
	apol_level_query_destroy(&query);
	apol_vector_destroy(&v);
	errno = error;
	return dict;
}

/**
 * Prints statistics regarding a policy's MLS categories.
 * If this function is given a name, it will attempt to
 * get statistics about a particular category; otherwise
 * the function gets statistics about all of the policy's
 * categories.
 *
 * @param name Reference to a MLS category's name; if NULL,
 * all categories will be considered
 * @param policydb Reference to a policy
 *
 * @return 0 on success, < 0 on error.
 */
static PyObject* get_cats(const char *name, const apol_policy_t * policydb)
{
	PyObject *obj = NULL;
	apol_cat_query_t *query = NULL;
	apol_vector_t *v = NULL;
	const qpol_cat_t *cat_datum = NULL;
	size_t i, n_cats;
	int error = 0;
	int rt;
	PyObject *list = PyList_New(0);
	if (!list) goto err;

	query = apol_cat_query_create();
	if (!query)
		goto err;
	if (apol_cat_query_set_cat(policydb, query, name))
		goto err;
	if (apol_cat_get_by_query(policydb, query, &v))
		goto err;
	n_cats = apol_vector_get_size(v);
	apol_vector_sort(v, &qpol_cat_datum_compare, (void *)policydb);

	for (i = 0; i < n_cats; i++) {
		cat_datum = apol_vector_get_element(v, i);
		if (!cat_datum)
			goto err;
		obj = get_cat_sens(cat_datum, policydb);
		if (!obj)
			goto err;
		rt = py_append_obj(list, obj);
		Py_DECREF(obj);
		if (rt) goto err;
	}

	if (name && !n_cats) {
		goto err;
	}

	goto cleanup;
err:
	error = errno;
	PyErr_SetString(PyExc_RuntimeError,strerror(errno));
	py_decref(list); list = NULL;
cleanup:
	apol_cat_query_destroy(&query);
	apol_vector_destroy(&v);
	errno = error;
	return list;
}

/**
 * Get the alias of a type.
 *
 * @param type_datum Reference to sepol type_datum
 * @param policydb Reference to a policy
 * attributes
 */
static PyObject* get_type_aliases(const qpol_type_t * type_datum, const apol_policy_t * policydb)
{
	qpol_iterator_t *iter = NULL;
	size_t alias_size;
	unsigned char isattr, isalias;
	const char *type_name = NULL;
	const char *alias_name;
	int error = 0;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);
	PyObject *list = PyList_New(0);
	if (!list) goto err;

	if (qpol_type_get_name(q, type_datum, &type_name))
		goto cleanup;
	if (qpol_type_get_isattr(q, type_datum, &isattr))
		goto cleanup;
	if (qpol_type_get_isalias(q, type_datum, &isalias))
		goto cleanup;

	if (qpol_type_get_alias_iter(q, type_datum, &iter))
		goto cleanup;
	if (qpol_iterator_get_size(iter, &alias_size))
		goto cleanup;
	if (alias_size >  0) {
		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
			if (qpol_iterator_get_item(iter, (void **)&alias_name))
				goto err;
			if (py_append_string(list, alias_name))
				goto err;
		}
	}
	goto cleanup;

err:
	error = errno;
	PyErr_SetString(PyExc_RuntimeError,strerror(errno));
	py_decref(list); list = NULL;

cleanup:
	qpol_iterator_destroy(&iter);
	errno = error;
	return list;
}

/**
 * Gets a textual representation of an attribute, and 
 * all of that attribute's types.
 *
 * @param type_datum Reference to sepol type_datum
 * @param policydb Reference to a policy
 */
static PyObject* get_attr(const qpol_type_t * type_datum, const apol_policy_t * policydb)
{
	PyObject *list = NULL;
	const qpol_type_t *attr_datum = NULL;
	qpol_iterator_t *iter = NULL;
	const char *attr_name = NULL, *type_name = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);
	unsigned char isattr;
	int error = 0;
	int rt = 0;
	PyObject *dict = PyDict_New(); 
	if (!dict) goto err;

	if (qpol_type_get_name(q, type_datum, &attr_name))
		goto err;

	if (py_insert_string(dict, "name", attr_name))
		goto err;

	/* get an iterator over all types this attribute has */
	if (qpol_type_get_isattr(q, type_datum, &isattr))
		goto err;

	if (isattr) {	       /* sanity check */
		if (qpol_type_get_type_iter(q, type_datum, &iter))
			goto err;
		list = PyList_New(0);
		if (!list) goto err;
		
		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
			if (qpol_iterator_get_item(iter, (void **)&attr_datum))
				goto err;
			if (qpol_type_get_name(q, attr_datum, &type_name))
				goto err;
			if (py_append_string(list, type_name))
				goto err;
		}
		qpol_iterator_destroy(&iter);
		rt = PyDict_SetItemString(dict, "types", list);
		Py_DECREF(list); list = NULL;
		if (rt) goto err;
	} else		       /* this should never happen */
		goto err;
	goto cleanup;

err:
	error = errno;
	PyErr_SetString(PyExc_RuntimeError,strerror(errno));
	py_decref(dict); dict = NULL;
	py_decref(list);

cleanup:
	qpol_iterator_destroy(&iter);
	errno =	error;
	return dict;
}

/**
 * Gets statistics regarding a policy's attributes.
 * If this function is given a name, it will attempt to
 * get statistics about a particular attribute; otherwise
 * the function gets statistics about all of the policy's
 * attributes.
 *
 * @param name Reference to an attribute's name; if NULL,
 * all object classes will be considered
 * @param policydb Reference to a policy
 *
 * @return 0 on success, < 0 on error.
 */
static PyObject* get_attribs(const char *name, const apol_policy_t * policydb)
{
	PyObject *obj;
	apol_attr_query_t *attr_query = NULL;
	apol_vector_t *v = NULL;
	const qpol_type_t *type_datum = NULL;
	size_t n_attrs, i;
	int error = 0;
	int rt = 0;
	PyObject *list = PyList_New(0);
	if (!list) goto err;

	/* we are only getting information about 1 attribute */
	if (name != NULL) {
		attr_query = apol_attr_query_create();
		if (!attr_query)
			goto err;
		if (apol_attr_query_set_attr(policydb, attr_query, name))
			goto err;
		if (apol_attr_get_by_query(policydb, attr_query, &v))
			goto err;
		apol_attr_query_destroy(&attr_query);
		if (apol_vector_get_size(v) == 0) {
			apol_vector_destroy(&v);
			errno = EINVAL;
			goto err;
		}

		type_datum = apol_vector_get_element(v, (size_t) 0);
		obj = get_attr(type_datum, policydb);
		rt = py_append_obj(list, obj);
		Py_DECREF(obj);
		if (rt) goto err;
	} else {
		attr_query = apol_attr_query_create();
		if (!attr_query)
			goto err;
		if (apol_attr_get_by_query(policydb, attr_query, &v))
			goto err;
		apol_attr_query_destroy(&attr_query);
		n_attrs = apol_vector_get_size(v);

		for (i = 0; i < n_attrs; i++) {
			/* get qpol_type_t* item from vector */
			type_datum = (qpol_type_t *) apol_vector_get_element(v, (size_t) i);
			if (!type_datum)
				goto err;
			obj = get_attr(type_datum, policydb);
			rt = py_append_obj(list, obj);
			Py_DECREF(obj);
			if (rt) goto err;
		}
	}
	apol_vector_destroy(&v);
	goto cleanup;

err:
	error = errno;
	PyErr_SetString(PyExc_RuntimeError,strerror(errno));
	py_decref(list); list = NULL;

cleanup:
	apol_attr_query_destroy(&attr_query);
	apol_vector_destroy(&v);
	errno = error;
	return list;
}

/**
 * Get a textual representation of a type, and
 * all of that type's attributes.
 *
 * @param type_datum Reference to sepol type_datum
 * @param policydb Reference to a policy
 */
static PyObject* get_type_attrs(const qpol_type_t * type_datum, const apol_policy_t * policydb)
{
	qpol_iterator_t *iter = NULL;
	const char *attr_name = NULL;
	const qpol_type_t *attr_datum = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);
	int error = 0;
	PyObject *list = PyList_New(0);
	if (!list) goto err;

	if (qpol_type_get_attr_iter(q, type_datum, &iter))
		goto err;

	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **)&attr_datum))
			goto err;
		if (qpol_type_get_name(q, attr_datum, &attr_name))
			goto err;
		if (py_append_string(list, attr_name))
			goto err;
	}
	goto cleanup;

err:
	error = errno;
	PyErr_SetString(PyExc_RuntimeError,strerror(errno));
	py_decref(list); list = NULL;

cleanup:
	qpol_iterator_destroy(&iter);
	errno = error;
	return list;
}

static PyObject* get_type(const qpol_type_t * type_datum, const apol_policy_t * policydb) {

	PyObject *obj;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);
	const char *type_name = NULL;
	int error = 0;
	int rt;
	unsigned char isalias, ispermissive, isattr;
	PyObject *dict = PyDict_New(); 
	if (!dict) goto err;

	if (qpol_type_get_name(q, type_datum, &type_name))
		goto err;
	if (qpol_type_get_isalias(q, type_datum, &isalias))
		goto err;
	if (qpol_type_get_isattr(q, type_datum, &isattr))
		goto err;
	if (qpol_type_get_ispermissive(q, type_datum, &ispermissive))
		goto err;

	if (py_insert_string(dict, "name", type_name))
		goto err;

	if (py_insert_bool(dict, "permissive", ispermissive))
		goto err;

	if (!isattr && !isalias) {
		obj = get_type_attrs(type_datum, policydb);
		rt = py_insert_obj(dict, "attributes", obj);
		Py_DECREF(obj);
		if (rt) goto err;
	}

	obj = get_type_aliases(type_datum, policydb);
	rt = py_insert_obj(dict, "aliases", obj);
	Py_DECREF(obj);
	if (rt) goto err;
	goto cleanup;

err:
	error = errno;
	PyErr_SetString(PyExc_RuntimeError,strerror(error));
	py_decref(dict); dict = NULL;

cleanup:
	errno = error; 
	return dict;
}

/**
 * Gets statistics regarding a policy's booleans.
 * If this function is given a name, it will attempt to
 * get statistics about a particular boolean; otherwise
 * the function gets statistics about all of the policy's booleans.
 *
 * @param name Reference to a boolean's name; if NULL,
 * all booleans will be considered
 * @param policydb Reference to a policy
 *
 * @return new reference, or NULL (setting an exception)
 */
static PyObject* get_booleans(const char *name, const apol_policy_t * policydb)
{
	PyObject *dict = NULL;
	int error = 0;
	int rt = 0;
	const char *bool_name = NULL;
	int state;
	qpol_bool_t *bool_datum = NULL;
	qpol_iterator_t *iter = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);
	size_t n_bools = 0;
	PyObject *list = PyList_New(0);
	if (!list) goto err;

	if (name != NULL) {
		if (qpol_policy_get_bool_by_name(q, name, &bool_datum))
			goto err;
		if (qpol_bool_get_state(q, bool_datum, &state))
			goto err;

		dict = PyDict_New(); 
		if (!dict) goto err;
		if (py_insert_string(dict, "name", name))
			goto err;
		if (py_insert_bool(dict, "name", state))
			goto err;
		rt = py_append_obj(list, dict);
		Py_DECREF(dict); dict = NULL;
		if (rt) goto err;
	} else {
		if (qpol_policy_get_bool_iter(q, &iter))
			goto err;
		if (qpol_iterator_get_size(iter, &n_bools))
			goto err;
		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
			if (qpol_iterator_get_item(iter, (void **)&bool_datum))
				goto err;
			if (qpol_bool_get_name(q, bool_datum, &bool_name))
				goto err;
			if (qpol_bool_get_state(q, bool_datum, &state))
				goto err;

			dict = PyDict_New(); 
			if (!dict) goto err;
			if (py_insert_string(dict, "name", bool_name))
				goto err;
			if (py_insert_bool(dict, "state", state))
				goto err;
			rt = py_append_obj(list, dict);
			Py_DECREF(dict); dict = NULL;
			if (rt) goto err;
		}
		qpol_iterator_destroy(&iter);
	}
	goto cleanup;

err:
	error = errno;
	PyErr_SetString(PyExc_RuntimeError,strerror(error));
	py_decref(list); list = NULL;
	py_decref(dict); dict = NULL;

cleanup:
	qpol_iterator_destroy(&iter);
	errno = error; 
	return list;
}

/**
 * Gets a textual representation of a user, and
 * all of that user's roles.
 *
 * @param type_datum Reference to sepol type_datum
 * @param policydb Reference to a policy
 * roles
 */
static PyObject* get_user(const qpol_user_t * user_datum, const apol_policy_t * policydb)
{
	int error = 0;
	int rt;
	const qpol_role_t *role_datum = NULL;
	qpol_iterator_t *iter = NULL;
	const qpol_mls_range_t *range = NULL;
	const qpol_mls_level_t *dflt_level = NULL;
	apol_mls_level_t *ap_lvl = NULL;
	apol_mls_range_t *ap_range = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);
	char *tmp = NULL;
	const char *user_name, *role_name;
	PyObject *dict = NULL;
	PyObject *list = PyList_New(0);
	if (!list) goto err;

	if (qpol_user_get_name(q, user_datum, &user_name))
		goto err;

	dict = PyDict_New(); 
	if (!dict) goto err;

	if (py_insert_string(dict, "name", user_name))
		goto err;

	if (qpol_policy_has_capability(q, QPOL_CAP_MLS)) {
		if (qpol_user_get_dfltlevel(q, user_datum, &dflt_level))
			goto err;
		ap_lvl = apol_mls_level_create_from_qpol_mls_level(policydb, dflt_level);
		tmp = apol_mls_level_render(policydb, ap_lvl);
		if (!tmp) goto err;
		if (py_insert_string(dict, "level", tmp))
		    goto err;
		free(tmp); tmp = NULL;

		if (qpol_user_get_range(q, user_datum, &range))
			goto err;
		ap_range = apol_mls_range_create_from_qpol_mls_range(policydb, range);
		tmp = apol_mls_range_render(policydb, ap_range);
		if (!tmp) goto err;
		if (py_insert_string(dict, "range", tmp))
		    goto err;
		free(tmp); tmp=NULL;
	}
	
	if (qpol_user_get_role_iter(q, user_datum, &iter))
		goto err;
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **)&role_datum))
			goto err;
		if (qpol_role_get_name(q, role_datum, &role_name))
			goto err;
		if (py_append_string(list, role_name))
			goto err;
	}

	rt = py_insert_obj(dict, "roles", list);
	Py_DECREF(list); list=NULL;
	if (rt) goto err;
	goto cleanup;

err:
	error = errno;
	PyErr_SetString(PyExc_RuntimeError,strerror(errno));
	py_decref(list); list=NULL;
	py_decref(dict); dict=NULL;

cleanup:
	free(tmp);
	qpol_iterator_destroy(&iter);
	apol_mls_level_destroy(&ap_lvl);
	apol_mls_range_destroy(&ap_range);
	errno = error;
	return dict;
}

/**
 * Prints a textual representation of an object class and possibly
 * all of that object class' permissions.
 *
 * @param type_datum Reference to sepol type_datum
 * @param policydb Reference to a policy
 */
static PyObject* get_class(const qpol_class_t * class_datum, const apol_policy_t * policydb)
{
	const char *class_name = NULL, *perm_name = NULL;
	qpol_iterator_t *iter = NULL;
	const qpol_common_t *common_datum = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);
	int error = 0;
	int rt;
	PyObject *list = NULL;
	PyObject *dict = PyDict_New();
	if (!dict) goto err;

	if (!class_datum)
		goto err;

	if (qpol_class_get_name(q, class_datum, &class_name))
		goto err;

	if (py_insert_string(dict, "name", class_name))
		goto err;
	/* get commons for this class */
	if (qpol_class_get_common(q, class_datum, &common_datum))
		goto err;

	list = PyList_New(0);
	if (!list) goto err;

	if (common_datum) {
		if (qpol_common_get_perm_iter(q, common_datum, &iter))
			goto err;
		/* print perms for the common */
		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
			if (qpol_iterator_get_item(iter, (void **)&perm_name))
				goto err;
			if (py_append_string(list, perm_name))
				goto err;
		}
	}
	/* print unique perms for this class */
	if (qpol_class_get_perm_iter(q, class_datum, &iter))
		goto err;
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **)&perm_name))
			goto err;
		if (py_append_string(list, perm_name))
			goto err;
	}
	rt = py_insert_obj(dict, "permlist", list);
	Py_DECREF(list); list = NULL;
	if (rt) goto err;
	qpol_iterator_destroy(&iter);
	goto cleanup;

err:
	error = errno;
	PyErr_SetString(PyExc_RuntimeError,strerror(errno));
	py_decref(list); list=NULL;
	py_decref(dict); dict=NULL;

cleanup:
	errno = error;
	qpol_iterator_destroy(&iter);
	return dict;
}

/**
 * Get statistics regarding a policy's object classes.
 * If this function is given a name, it will attempt to
 * print statistics about a particular object class; otherwise
 * the function prints statistics about all of the policy's object
 * classes.
 *
 * @param name Reference to an object class' name; if NULL,
 * all object classes will be considered
 * @param policydb Reference to a policy
 *
 * @return 0 on success, < 0 on error.
 */
static PyObject*  get_classes(const char *name, const apol_policy_t * policydb)
{
	qpol_iterator_t *iter = NULL;
	size_t n_classes = 0;
	const qpol_class_t *class_datum = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);
	int error = 0;
	int rt;
	PyObject *obj;
	PyObject *list = PyList_New(0);
	if (!list) goto err;

	if (name != NULL) {
		if (qpol_policy_get_class_by_name(q, name, &class_datum))
			goto err;
		obj = get_class(class_datum, policydb);
		rt = py_append_obj(list, obj);
		Py_DECREF(obj);
		if (rt) goto err;
	} else {
		if (qpol_policy_get_class_iter(q, &iter))
			goto err;
		if (qpol_iterator_get_size(iter, &n_classes))
			goto err;

		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
			if (qpol_iterator_get_item(iter, (void **)&class_datum))
				goto err;
			obj = get_class(class_datum, policydb);
			rt = py_append_obj(list, obj);
			Py_DECREF(obj);
			if (rt) goto err;
		}
		qpol_iterator_destroy(&iter);
	}
	goto cleanup;
err:
	error = errno;
	PyErr_SetString(PyExc_RuntimeError,strerror(errno));
	py_decref(list); list = NULL;

cleanup:
	qpol_iterator_destroy(&iter);
	errno = error;
	return list;
}

/**
 * Gets statistics regarding a policy's users.
 * If this function is given a name, it will attempt to
 * get statistics about a particular user; otherwise
 * the function gets statistics about all of the policy's
 * users.
 *
 * @param name Reference to a user's name; if NULL,
 * all users will be considered
 * @param policydb Reference to a policy
 *
 * @return 0 on success, < 0 on error.
 */
static PyObject*  get_users(const char *name, const apol_policy_t * policydb)
{
	qpol_iterator_t *iter = NULL;
	const qpol_user_t *user_datum = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);
	int error = 0;
	int rt;
	PyObject *obj;
	PyObject *list = PyList_New(0);
	if (!list) goto err;

	if (name != NULL) {
		if (qpol_policy_get_user_by_name(q, name, &user_datum)) {
			errno = EINVAL;
			goto err;
		}
		obj = get_user(user_datum, policydb);
		rt = py_append_obj(list, obj);
		Py_DECREF(obj);
		if (rt) goto err;
	} else {
		if (qpol_policy_get_user_iter(q, &iter))
			goto err;

		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
			if (qpol_iterator_get_item(iter, (void **)&user_datum))
				goto err;
			obj = get_user(user_datum, policydb);
			rt = py_append_obj(list, obj);
			Py_DECREF(obj);
			if (rt) goto err;
		}
		qpol_iterator_destroy(&iter);
	}
	goto cleanup;

err:
	error = errno;
	PyErr_SetString(PyExc_RuntimeError,strerror(errno));
	py_decref(list); list = NULL;

cleanup:
	qpol_iterator_destroy(&iter);
	errno = error;
	return list;
}

/**
 * get a textual representation of a role, and 
 * all of that role's types.
 *
 * @param type_datum Reference to sepol type_datum
 * @param policydb Reference to a policy
 * types
 */
static PyObject* get_role(const qpol_role_t * role_datum, const apol_policy_t * policydb)
{
	const char *role_name = NULL, *type_name = NULL;
	const qpol_role_t *dom_datum = NULL;
	const qpol_type_t *type_datum = NULL;
	qpol_iterator_t *iter = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);
	size_t n_dom = 0, n_types = 0;
	int error = 0;
	int rt;
	PyObject *list = NULL;
	PyObject *dict = PyDict_New();
	if (!dict) goto err;

	if (qpol_role_get_name(q, role_datum, &role_name))
		goto err;
	if (py_insert_string(dict, "name", role_name))
		goto err;

	if (qpol_role_get_dominate_iter(q, role_datum, &iter))
		goto err;
	if (qpol_iterator_get_size(iter, &n_dom))
		goto err;
	if ((int)n_dom > 0) {
		list = PyList_New(0);
		if (!list) goto err;
		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
			if (qpol_iterator_get_item(iter, (void **)&dom_datum))
				goto err;
			if (qpol_role_get_name(q, dom_datum, &role_name))
				goto err;
			if (py_append_string(list, role_name))
				goto err;
		}
		rt = py_insert_obj(dict, "roles", list);
		Py_DECREF(list); list = NULL;
		if (rt) goto err;
	}
	qpol_iterator_destroy(&iter);
	
	if (qpol_role_get_type_iter(q, role_datum, &iter))
		goto err;
	if (qpol_iterator_get_size(iter, &n_types))
		goto err;
	if ((int)n_types > 0) {
		list = PyList_New(0);
		if (!list) goto err;
		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
			if (qpol_iterator_get_item(iter, (void **)&type_datum))
				goto err;
			if (qpol_type_get_name(q, type_datum, &type_name))
				goto err;
			if (py_append_string(list, type_name))
				goto err;
		}
		rt = py_insert_obj(dict, "types", list);
		Py_DECREF(list); list = NULL;
		if (rt) goto err;
	}
	goto cleanup;

err:
	error = errno;
	PyErr_SetString(PyExc_RuntimeError,strerror(errno));
	py_decref(list); list = NULL;
	py_decref(dict); dict = NULL;

cleanup:
	qpol_iterator_destroy(&iter);
	errno =	error;
	return dict;
}

/**
 * Get statistics regarding a policy's ports.
 * If this function is given a name, it will attempt to
 * get statistics about a particular port; otherwise
 * the function get statistics about all of the policy's ports.
 *
 * @param name Reference to an port's name; if NULL,
 * all ports will be considered
 * @param policydb Reference to a policy
 *
 * @return 0 on success, < 0 on error.
 */
static PyObject*  get_ports(const char *num, const apol_policy_t * policydb)
{
	const qpol_portcon_t *portcon = NULL;
	qpol_iterator_t *iter = NULL;
	uint16_t low_port, high_port;
	uint8_t ocon_proto;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);
	const qpol_context_t *ctxt = NULL;
	const char *proto_str = NULL;
	const char *type = NULL;
	const apol_mls_range_t *range = NULL;
	char *range_str = NULL;
	apol_context_t *c = NULL;
	int error = 0;
	int rt = 0;
	PyObject *dict = NULL;
	PyObject *list = PyList_New(0);
	if (!list) goto err;

	if (qpol_policy_get_portcon_iter(q, &iter))
		goto err;

	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **)&portcon))
			goto err;
		if (qpol_portcon_get_low_port(q, portcon, &low_port))
			goto err;
		if (qpol_portcon_get_high_port(q, portcon, &high_port))
			goto err;
		if (qpol_portcon_get_protocol(q, portcon, &ocon_proto))
			goto err;
		if (num) {
			if (atoi(num) < low_port || atoi(num) > high_port)
				continue;
		}

		if ((ocon_proto != IPPROTO_TCP) &&
		    (ocon_proto != IPPROTO_UDP)) 
			goto err;

		if (qpol_portcon_get_context(q, portcon, &ctxt)) {
			PyErr_SetString(PyExc_RuntimeError, "Could not get for port context.");
			goto err;
		}

		if ((proto_str = apol_protocol_to_str(ocon_proto)) == NULL) {
			PyErr_SetString(PyExc_RuntimeError, "Invalid protocol for port");
			goto err;
		}

		if ((c = apol_context_create_from_qpol_context(policydb, ctxt)) == NULL) {
			goto err;
		}
		
		if((type = apol_context_get_type(c)) == NULL) {
			apol_context_destroy(&c);
			goto err;
		}
			
		dict = PyDict_New(); 
		if (!dict) goto err;
		if (py_insert_string(dict, "type", type))
			goto err;

		if((range = apol_context_get_range(c)) != NULL) {
			range_str = apol_mls_range_render(policydb, range);
			if (range_str == NULL) {
				goto err;
			}
			if (py_insert_string(dict, "range", range_str))
				goto err;
		}

		if (py_insert_string(dict, "protocol", proto_str))
			goto err;

		if (py_insert_long(dict, "high", high_port))
			goto err;

		if (py_insert_long(dict, "low", low_port))
			goto err;

		rt = py_append_obj(list, dict);
		Py_DECREF(dict); dict = NULL;
		if (rt) goto err;
	}
	goto cleanup;

err:
	error = errno;
	PyErr_SetString(PyExc_RuntimeError,strerror(errno));
	py_decref(list); list = NULL;
	py_decref(dict); dict = NULL;

cleanup:
	free(range_str);
	apol_context_destroy(&c);
	qpol_iterator_destroy(&iter);
	errno = error;
	return list;
}

/**
 * Get statistics regarding a policy's roles.
 * If this function is given a name, it will attempt to
 * get statistics about a particular role; otherwise
 * the function get statistics about all of the policy's roles.
 *
 * @param name Reference to an role's name; if NULL,
 * all roles will be considered
 * @param policydb Reference to a policy
 *
 * @return 0 on success, < 0 on error.
 */
static PyObject*  get_roles(const char *name, const apol_policy_t * policydb)
{
	const qpol_role_t *role_datum = NULL;
	qpol_iterator_t *iter = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);
	int error = 0;
	int rt;
	PyObject *obj;
	PyObject *list = PyList_New(0);
	if (!list) goto err;

	if (name != NULL) {
		if (qpol_policy_get_role_by_name(q, name, &role_datum)) {
			errno = EINVAL;
			goto err;
		}
		obj = get_role(role_datum, policydb);
		rt = py_append_obj(list, obj);
		Py_DECREF(obj); 
		if (rt) goto err;
	} else {
		if (qpol_policy_get_role_iter(q, &iter))
			goto err;

		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
			if (qpol_iterator_get_item(iter, (void **)&role_datum))
				goto err;
			obj = get_role(role_datum, policydb);
			rt = py_append_obj(list, obj);
			Py_DECREF(obj); 
			if (rt) goto err;
		}
		qpol_iterator_destroy(&iter);
	}
	goto cleanup;

err:
	error = errno;
	PyErr_SetString(PyExc_RuntimeError,strerror(errno));
	py_decref(list); list = NULL;

cleanup:
	qpol_iterator_destroy(&iter);
	errno = error;
	return list;
}

/**
 * Get statistics regarding a policy's types.
 * If this function is given a name, it will attempt to
 * print statistics about a particular type; otherwise
 * the function prints statistics about all of the policy's types.
 *
 * @param name Reference to a type's name; if NULL,
 * all object classes will be considered
 * @param policydb Reference to a policy
 *
 * @return 0 on success, < 0 on error.
 */
static PyObject* get_types(const char *name, const apol_policy_t * policydb)
{
	const qpol_type_t *type_datum = NULL;
	qpol_iterator_t *iter = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);
	int error = 0;
	int rt;
	PyObject *obj;
	PyObject *list = PyList_New(0);
	if (!list) goto err;
	/* if name was provided, only print that name */
	if (name != NULL) {
		if (qpol_policy_get_type_by_name(q, name, &type_datum)) {
			errno = EINVAL;
			goto err;
		}
		obj = get_type(type_datum, policydb);
		rt = py_append_obj(list, obj);
		Py_DECREF(obj); 
		if (rt) goto err;
	} else {
		if (qpol_policy_get_type_iter(q, &iter))
			goto err;

		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
			if (qpol_iterator_get_item(iter, (void **)&type_datum))
				goto err;
			obj = get_type(type_datum, policydb);
			rt = py_append_obj(list, obj);
			Py_DECREF(obj); 
			if (rt) goto err;
		}
	}
	goto cleanup;

err:
	error = errno;
	PyErr_SetString(PyExc_RuntimeError,strerror(errno));
	py_decref(list); list = NULL;

cleanup:
	qpol_iterator_destroy(&iter);
	errno =	error;
	return list;
}

PyObject* info( int type, const char *name)
{
	PyObject* output = NULL;

	switch(type) {
	/* display requested info */
	case TYPE:
		output = get_types(name, policy);
		break;
	case ATTRIBUTE:
		output = get_attribs(name, policy);
		break;
	case ROLE:
		output = get_roles(name, policy);
		break;
	case USER:
		output = get_users(name, policy);
		break;
	case CLASS:
		output = get_classes(name, policy);
		break;
	case BOOLEAN:
		output = get_booleans(name, policy);
		break;
	case PORT:
		output = get_ports(name, policy);
		break;
	case SENS:
		output = get_sens(name, policy);
		break;
	case CATS:
		output = get_cats(name, policy);
		break;
	default:
		errno = EINVAL;
		PyErr_SetString(PyExc_RuntimeError,strerror(errno));
		break;
	}

	return output;
}

PyObject *wrap_info(PyObject *UNUSED(self), PyObject *args){
    int type;
    const char *name;
    
    if (!policy) {
	    PyErr_SetString(PyExc_RuntimeError,"Policy not loaded");
	    return NULL;
    }

    if (!PyArg_ParseTuple(args, "iz", &type, &name))
        return NULL;

    return info(type, name);
}

void init_info (PyObject *m) {
    PyModule_AddIntConstant(m, "ATTRIBUTE", ATTRIBUTE);
    PyModule_AddIntConstant(m, "PORT", PORT);
    PyModule_AddIntConstant(m, "ROLE", ROLE);
    PyModule_AddIntConstant(m, "TYPE", TYPE);
    PyModule_AddIntConstant(m, "USER", USER);
    PyModule_AddIntConstant(m, "CLASS", CLASS);
    PyModule_AddIntConstant(m, "BOOLEAN", BOOLEAN);
    PyModule_AddIntConstant(m, "SENS", SENS);
    PyModule_AddIntConstant(m, "CATS", CATS);
}
