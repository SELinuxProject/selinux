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

#if PY_MAJOR_VERSION >= 3
#	define PyIntObject                  PyLongObject
#	define PyInt_Type                   PyLong_Type
#	define PyInt_Check(op)              PyLong_Check(op)
#	define PyInt_CheckExact(op)         PyLong_CheckExact(op)
#	define PyInt_FromString             PyLong_FromString
#	define PyInt_FromUnicode            PyLong_FromUnicode
#	define PyInt_FromLong               PyLong_FromLong
#	define PyInt_FromSize_t             PyLong_FromSize_t
#	define PyInt_FromSsize_t            PyLong_FromSsize_t
#	define PyInt_AsLong                 PyLong_AsLong
#	define PyInt_AS_LONG                PyLong_AS_LONG
#	define PyInt_AsSsize_t              PyLong_AsSsize_t
#	define PyInt_AsUnsignedLongMask     PyLong_AsUnsignedLongMask
#	define PyInt_AsUnsignedLongLongMask PyLong_AsUnsignedLongLongMask
#	define PyString_FromString          PyUnicode_FromString
#	define PyString_AsString            PyUnicode_AsUTF8
#endif

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


