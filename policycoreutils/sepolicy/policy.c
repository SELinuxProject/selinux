/**
 *  @file
 *  Python bindings to search SELinux Policy rules.
 *
 *  @author Dan Walsh  <dwalsh@redhat.com>
 *
 *  Copyright (C) 2012 Red Hat, INC
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

#include "Python.h"

#ifdef UNUSED
#elif defined(__GNUC__)
# define UNUSED(x) UNUSED_ ## x __attribute__((unused))
#elif defined(__LCLINT__)
# define UNUSED(x) /*@unused@*/ x
#else
# define UNUSED(x) x
#endif

#include "policy.h"
apol_policy_t *policy = NULL;

/* other */
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#define COPYRIGHT_INFO "Copyright (C) 2003-2007 Tresys Technology, LLC"

PyObject *wrap_policy(PyObject *UNUSED(self), PyObject *args){
    const char *policy_file;
    apol_vector_t *mod_paths = NULL;
    apol_policy_path_type_e path_type = APOL_POLICY_PATH_TYPE_MONOLITHIC;
    apol_policy_path_t *pol_path = NULL;
    
    if (!PyArg_ParseTuple(args, "z", &policy_file))
	    return NULL;

    if (policy) 
	    apol_policy_destroy(&policy);

    int policy_load_options = 0;
	    
    pol_path = apol_policy_path_create(path_type, policy_file, mod_paths);
    if (!pol_path) {
	    apol_vector_destroy(&mod_paths);
	    PyErr_SetString(PyExc_RuntimeError,strerror(ENOMEM));
	    return NULL;
    }
    apol_vector_destroy(&mod_paths);
    
    policy = apol_policy_create_from_policy_path(pol_path, policy_load_options, NULL, NULL);
    apol_policy_path_destroy(&pol_path);
    if (!policy) {
	    PyErr_SetString(PyExc_RuntimeError,strerror(errno));
	    return NULL;
    }

    return Py_None;
}

static PyMethodDef methods[] = {
	{"policy", (PyCFunction) wrap_policy, METH_VARARGS,
		 "Initialize SELinux policy for use with search and info"},
	{"info", (PyCFunction) wrap_info, METH_VARARGS,
		 "Return SELinux policy info about types, attributes, roles, users"},
	{"search", (PyCFunction) wrap_search, METH_VARARGS,
	"Search SELinux Policy for allow, neverallow, auditallow, dontaudit and transition records"},
	{NULL, NULL, 0, NULL}	/* sentinel */
};

void init_policy(void) {
PyObject *m;
m = Py_InitModule("_policy", methods);
init_info(m);
}
