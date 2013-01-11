#include "Python.h"

#ifdef UNUSED
#elif defined(__GNUC__)
# define UNUSED(x) UNUSED_ ## x __attribute__((unused))
#elif defined(__LCLINT__)
# define UNUSED(x) /*@unused@*/ x
#else
# define UNUSED(x) x
#endif

#define py_decref(x) { if (x) 	Py_DECREF(x); }

static int py_append_string(PyObject *list, const char* value)
{
	int rt;
	PyObject *obj = PyString_FromString(value);
	if (!obj) return -1;
	rt = PyList_Append(list, obj);
	Py_DECREF(obj);
	return rt;
}

static int py_append_obj(PyObject *list, PyObject *obj)
{
	int rt;
	if (!obj) return -1;
	rt = PyList_Append(list, obj);
	return rt;
}

static int py_insert_obj(PyObject *dict, const char *name, PyObject *obj)
{
	int rt;
	if (!obj) return -1;
	rt = PyDict_SetItemString(dict, name, obj);
	return rt;
}

static int py_insert_string(PyObject *dict, const char *name, const char* value)
{
	int rt;
	PyObject *obj = PyString_FromString(value);
	if (!obj) return -1;
	rt = PyDict_SetItemString(dict, name, obj);
	Py_DECREF(obj);
	return rt;
}


