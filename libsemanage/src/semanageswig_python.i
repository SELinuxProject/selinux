/* Author: Spencer Shimko <sshimko@tresys.com>
 *
 * Copyright (C) 2004-2005 Tresys Technology, LLC
 * Copyright (C) 2006 Red Hat, Inc
 *  
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

/** standard typemaps **/

%header %{
	#include <stdlib.h>
	#include <semanage/semanage.h>
	#include <sys/mman.h>

	#define STATUS_SUCCESS 0
	#define STATUS_ERR -1
%}

%include "stdint.i"
%ignore semanage_module_install_pp;
%ignore semanage_module_install_hll;

%wrapper %{


	/* There are two ways to call this function:
	 * One is with a valid swig_type and destructor.
	 * Two is with a NULL swig_type and NULL destructor. 
	 * 
	 * In the first mode, the function converts
	 * an array of *cloned* objects [of the given pointer swig type] 
	 * into a PyList, and destroys the array in the process 
	 * (the objects pointers are preserved).
	 *
	 * In the second mode, the function converts
	 * an array of *constant* strings into a PyList, and destroys
	 * the array in the process 
	 * (the strings are copied, originals not freed). */

	static int semanage_array2plist(
		semanage_handle_t* handle,
		void** arr, 
		unsigned int asize, 
		swig_type_info* swig_type,
		void (*destructor) (void*),	
		PyObject** result) {
		
		PyObject* plist = PyList_New(0);
		unsigned int i;

		if (!plist) 
			goto err;
	
		for (i = 0; i < asize; i++)  {
			
			PyObject* obj = NULL;

			/* NULL indicates string conversion,
			 * otherwise create an opaque pointer */
			if (!swig_type)
				obj = SWIG_FromCharPtr(arr[i]);
			else
				obj = SWIG_NewPointerObj(arr[i], swig_type, 0);				 

			if (!obj) 
				goto err;

			if (PyList_Append(plist, obj) < 0) 
				goto err;
		}

		free(arr);
		
		*result = plist;		
		return STATUS_SUCCESS;

		err:
		for (i = 0; i < asize; i++) 
			if (destructor)
				destructor(arr[i]);
		free(arr);
		return STATUS_ERR;
	}
%} 
/* a few helpful typemaps are available in this library */
%include <typemaps.i>
/* wrap all int*'s so they can be used for results 
   if it becomes necessary to send in data this should be changed to INOUT */
%apply int *OUTPUT { int * };
%apply int *OUTPUT { size_t * };
%apply int *OUTPUT { unsigned int * };
%apply int *OUTPUT { uint16_t * };

%include <cstring.i>
/* This is needed to properly mmaped binary data in SWIG */
%cstring_output_allocate_size(void **mapped_data, size_t *data_len, munmap(*$1, *$2));

%typemap(in, numinputs=0) char **(char *temp=NULL) {
	$1 = &temp;
}

%typemap(argout) char** {
	$result = SWIG_Python_AppendOutput($result, SWIG_FromCharPtr(*$1));
	free(*$1);
}

%typemap(in, numinputs=0) char ***(char **temp=NULL) {
	$1 = &temp;
}

%typemap(argout) (
 	semanage_handle_t* handle,
	const semanage_user_t* user,
	const char*** roles_arr, 
	unsigned int* num_roles) {

	if ($result) {	
		int value;
		SWIG_AsVal_int($result, &value);
		if (value >= 0) {
			PyObject* plist = NULL;
			if (semanage_array2plist($1, (void**) *$3, *$4,
                        	NULL, NULL, &plist) < 0)
				$result = SWIG_From_int(STATUS_ERR);
			else
				$result = SWIG_Python_AppendOutput($result, plist);
		}
	}
}

/** module typemaps**/

/* the wrapper will setup this parameter for passing... the resulting python functions
   will not take the semanage_module_info_t ** parameter */
%typemap(in, numinputs=0) semanage_module_info_t **(semanage_module_info_t *temp=NULL) {
	$1 = &temp;
}

%typemap(argout) semanage_module_info_t ** {
	$result = SWIG_Python_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
}

/** module key typemaps **/

/* the wrapper will setup this parameter for passing... the resulting python functions
   will not take the semanage_module_key_t ** parameter */
%typemap(in, numinputs=0) semanage_module_key_t **(semanage_module_key_t *temp=NULL) {
	$1 = &temp;
}

%typemap(argout) semanage_module_key_t ** {
	$result = SWIG_Python_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
}

/** context typemaps **/

/* the wrapper will setup this parameter for passing... the resulting python functions
   will not take the semanage_context_t ** parameter */
%typemap(in, numinputs=0) semanage_context_t **(semanage_context_t *temp=NULL) {
	$1 = &temp;
}

%typemap(argout) semanage_context_t** {
	$result = SWIG_Python_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
}

/** boolean typemaps **/

/* the wrapper will setup this parameter for passing... the resulting python functions
   will not take the semanage_bool_t *** parameter */
%typemap(in, numinputs=0) semanage_bool_t ***(semanage_bool_t **temp=NULL) {
	$1 = &temp;
}

%typemap(argout) (
 	semanage_handle_t* handle,
	semanage_bool_t*** records, 
	unsigned int* count) {

	if ($result) {	
		int value;
		SWIG_AsVal_int($result, &value);
		if (value >= 0) {
			PyObject* plist = NULL;
			if (semanage_array2plist($1, (void**) *$2, *$3, SWIGTYPE_p_semanage_bool,
				(void (*) (void*)) &semanage_bool_free, &plist) < 0)
				$result = SWIG_From_int(STATUS_ERR);
			else
		   	        $result = SWIG_Python_AppendOutput($result, plist);
		}
	}
}

%typemap(in, numinputs=0) semanage_bool_t **(semanage_bool_t *temp=NULL) {
	$1 = &temp;
}

%typemap(argout) semanage_bool_t ** {
	$result = SWIG_Python_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
}

%typemap(argout) semanage_bool_key_t ** {
	$result = SWIG_Python_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
}

%typemap(in, numinputs=0) semanage_bool_key_t **(semanage_bool_key_t *temp=NULL) {
	$1 = &temp;
}

/** fcontext typemaps **/

/* the wrapper will setup this parameter for passing... the resulting python functions
   will not take the semanage_fcontext_t *** parameter */
%typemap(in, numinputs=0) semanage_fcontext_t ***(semanage_fcontext_t **temp=NULL) {
        $1 = &temp;
}

%typemap(argout) (
 	semanage_handle_t* handle,
	semanage_fcontext_t*** records, 
	unsigned int* count) {

	if ($result) {	
		int value;
		SWIG_AsVal_int($result, &value);
		if (value >= 0) {
			PyObject* plist = NULL;
			if (semanage_array2plist($1, (void**) *$2, *$3, SWIGTYPE_p_semanage_fcontext,
				(void (*) (void*)) &semanage_fcontext_free, &plist) < 0)
				$result = SWIG_From_int(STATUS_ERR);
			else
				$result = SWIG_Python_AppendOutput($result, plist);
		}
	}
}

%typemap(in, numinputs=0) semanage_fcontext_t **(semanage_fcontext_t *temp=NULL) {
        $1 = &temp;
}

%typemap(argout) semanage_fcontext_t ** {
	$result = SWIG_Python_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
}

%typemap(argout) semanage_fcontext_key_t ** {
        $result = SWIG_Python_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
}

%typemap(in, numinputs=0) semanage_fcontext_key_t **(semanage_fcontext_key_t *temp=NULL) {
        $1 = &temp;
}

/** interface typemaps **/

/* the wrapper will setup this parameter for passing... the resulting python functions
   will not take the semanage_iface_t *** parameter */
%typemap(in, numinputs=0) semanage_iface_t ***(semanage_iface_t **temp=NULL) {
	$1 = &temp;
}


%typemap(argout) (
 	semanage_handle_t* handle,
	semanage_iface_t*** records, 
	unsigned int* count) {

	if ($result) {	
		int value;
		SWIG_AsVal_int($result, &value);
		if (value >= 0) {
			PyObject* plist = NULL;
			if (semanage_array2plist($1, (void**) *$2, *$3, SWIGTYPE_p_semanage_iface,
				(void (*) (void*)) &semanage_iface_free, &plist) < 0)
				$result = SWIG_From_int(STATUS_ERR);
			else
				$result = SWIG_Python_AppendOutput($result, plist);
		}
	}
}

%typemap(in, numinputs=0) semanage_iface_t **(semanage_iface_t *temp=NULL) {
	$1 = &temp;
}

%typemap(argout) semanage_iface_t ** {
	$result = SWIG_Python_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
}

%typemap(argout) semanage_iface_key_t ** {
	$result = SWIG_Python_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
}

%typemap(in, numinputs=0) semanage_iface_key_t **(semanage_iface_key_t *temp=NULL) {
	$1 = &temp;
}

/** seuser typemaps **/

/* the wrapper will setup this parameter for passing... the resulting python functions
   will not take the semanage_seuser_t *** parameter */
%typemap(in, numinputs=0) semanage_seuser_t ***(semanage_seuser_t **temp=NULL) {
	$1 = &temp;
}


%typemap(argout) (
 	semanage_handle_t* handle,
	semanage_seuser_t*** records, 
	unsigned int* count) {

	if ($result) {	
		int value;
		SWIG_AsVal_int($result, &value);
		if (value >= 0) {
			PyObject* plist = NULL;
			if (semanage_array2plist($1, (void**) *$2, *$3, SWIGTYPE_p_semanage_seuser,
				(void (*) (void*)) &semanage_seuser_free, &plist) < 0)
				$result = SWIG_From_int(STATUS_ERR);
			else
				$result = SWIG_Python_AppendOutput($result, plist);
		}
	}
}

%typemap(in, numinputs=0) semanage_seuser_t **(semanage_seuser_t *temp=NULL) {
	$1 = &temp;
}

%typemap(argout) semanage_seuser_t ** {
	$result = SWIG_Python_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
}

%typemap(argout) semanage_seuser_key_t ** {
	$result = SWIG_Python_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
}

%typemap(in, numinputs=0) semanage_seuser_key_t **(semanage_seuser_key_t *temp=NULL) {
	$1 = &temp;
}

/** user typemaps **/

/* the wrapper will setup this parameter for passing... the resulting python functions
   will not take the semanage_user_t *** parameter */
%typemap(in, numinputs=0) semanage_user_t ***(semanage_user_t **temp=NULL) {
	$1 = &temp;
}

%typemap(argout) (
 	semanage_handle_t* handle,
	semanage_user_t*** records, 
	unsigned int* count) {

	if ($result) {	
		int value;
		SWIG_AsVal_int($result, &value);
		if (value >= 0) {
			PyObject* plist = NULL;
			if (semanage_array2plist($1, (void**) *$2, *$3, SWIGTYPE_p_semanage_user,
				(void (*) (void*)) &semanage_user_free, &plist) < 0)
				$result = SWIG_From_int(STATUS_ERR);
			else
				$result = SWIG_Python_AppendOutput($result, plist);
		}
	}
}

%typemap(in, numinputs=0) semanage_user_t **(semanage_user_t *temp=NULL) {
	$1 = &temp;
}

%typemap(argout) semanage_user_t ** {
	$result = SWIG_Python_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
}

%typemap(argout) semanage_user_key_t ** {
	$result = SWIG_Python_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
}

%typemap(in, numinputs=0) semanage_user_key_t **(semanage_user_key_t *temp=NULL) {
	$1 = &temp;
}

/** port typemaps **/

/* the wrapper will setup this parameter for passing... the resulting python functions
   will not take the semanage_port_t *** parameter */
%typemap(in, numinputs=0) semanage_port_t ***(semanage_port_t **temp=NULL) {
	$1 = &temp;
}

%typemap(argout) (
 	semanage_handle_t* handle,
	semanage_port_t*** records, 
	unsigned int* count) {

	if ($result) {	
		int value;
		SWIG_AsVal_int($result, &value);
		if (value >= 0) {
			PyObject* plist = NULL;
			if (semanage_array2plist($1, (void**) *$2, *$3, SWIGTYPE_p_semanage_port,
				(void (*) (void*)) &semanage_port_free, &plist) < 0)
				$result = SWIG_From_int(STATUS_ERR);
			else
				$result = SWIG_Python_AppendOutput($result, plist);
		}
	}
}

%typemap(in, numinputs=0) semanage_port_t **(semanage_port_t *temp=NULL) {
	$1 = &temp;
}

%typemap(argout) semanage_port_t ** {
	$result = SWIG_Python_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
}

%typemap(argout) semanage_port_key_t ** {
	$result = SWIG_Python_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
}

%typemap(in, numinputs=0) semanage_port_key_t **(semanage_port_key_t *temp=NULL) {
	$1 = &temp;
}

/** node typemaps **/

/* the wrapper will setup this parameter for passing... the resulting python functions
   will not take the semanage_node_t *** parameter */
%typemap(in, numinputs=0) semanage_node_t ***(semanage_node_t **temp=NULL) {
	$1 = &temp;
}

%typemap(argout) (
 	semanage_handle_t* handle,
	semanage_node_t*** records, 
	unsigned int* count) {

	if ($result) {	
		int value;
		SWIG_AsVal_int($result, &value);
		if (value >= 0) {
			PyObject* plist = NULL;
			if (semanage_array2plist($1, (void**) *$2, *$3, SWIGTYPE_p_semanage_node,
				(void (*) (void*)) &semanage_node_free, &plist) < 0)
				$result = SWIG_From_int(STATUS_ERR);
			else
				$result = SWIG_Python_AppendOutput($result, plist);
		}
	}
}

%typemap(in, numinputs=0) semanage_node_t **(semanage_node_t *temp=NULL) {
	$1 = &temp;
}

%typemap(argout) semanage_node_t ** {
	$result = SWIG_Python_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
}


%typemap(argout) semanage_node_key_t ** {
	$result = SWIG_Python_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
}

%typemap(in, numinputs=0) semanage_node_key_t **(semanage_node_key_t *temp=NULL) {
	$1 = &temp;
}

%include "semanageswig_python_exception.i"
%include "semanageswig.i"
