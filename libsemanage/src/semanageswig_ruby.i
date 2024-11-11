/* Author Dave Quigley
 * based on semanageswig_python.i by Spencer Shimko
 */

%header %{
        #include <stdlib.h>
        #include <semanage/semanage.h>

        #define STATUS_SUCCESS 0
        #define STATUS_ERR -1
%}
/* a few helpful typemaps are available in this library */
%include <typemaps.i>

/* wrap all int*'s so they can be used for results
   if it becomes necessary to send in data this should be changed to INOUT */
%apply int *OUTPUT { int * };
%apply int *OUTPUT { size_t * };
%apply int *OUTPUT { unsigned int * };

%typemap(in, numinputs=0) char **(char *temp=NULL) {
        $1 = &temp;
}

%typemap(argout) char** {
        %append_output(SWIG_FromCharPtr(*$1));
        free(*$1);
}

%typemap(in, numinputs=0) char ***(char **temp=NULL) {
        $1 = &temp;
}

/* the wrapper will setup this parameter for passing... the resulting ruby functions
   will not take the semanage_module_info_t ** parameter */
%typemap(in, numinputs=0) semanage_module_info_t **(semanage_module_info_t *temp=NULL) {
        $1 = &temp;
}

%typemap(argout) semanage_module_info_t ** {
        $result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
}

/** context typemaps **/

/* the wrapper will setup this parameter for passing... the resulting python functions
   will not take the semanage_context_t ** parameter */
%typemap(in, numinputs=0) semanage_context_t **(semanage_context_t *temp=NULL) {
        $1 = &temp;
}

%typemap(argout) semanage_context_t** {
        $result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
}

/** boolean typemaps **/

/* the wrapper will setup this parameter for passing... the resulting python functions
   will not take the semanage_bool_t *** parameter */
%typemap(in, numinputs=0) semanage_bool_t ***(semanage_bool_t **temp=NULL) {
        $1 = &temp;
}

%typemap(in, numinputs=0) semanage_bool_t **(semanage_bool_t *temp=NULL) {
        $1 = &temp;
}

%typemap(argout) semanage_bool_t ** {
        $result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
}

%typemap(argout) semanage_bool_key_t ** {
        $result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
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

%typemap(in, numinputs=0) semanage_fcontext_t **(semanage_fcontext_t *temp=NULL) {
        $1 = &temp;
}

%typemap(argout) semanage_fcontext_t ** {
        $result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
}

%typemap(argout) semanage_fcontext_key_t ** {
        $result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
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

%typemap(in, numinputs=0) semanage_iface_t **(semanage_iface_t *temp=NULL) {
        $1 = &temp;
}

%typemap(argout) semanage_iface_t ** {
        $result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
}

%typemap(argout) semanage_iface_key_t ** {
        $result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
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

%typemap(in, numinputs=0) semanage_seuser_t **(semanage_seuser_t *temp=NULL) {
        $1 = &temp;
}

%typemap(argout) semanage_seuser_t ** {
        $result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
}

%typemap(argout) semanage_seuser_key_t ** {
        $result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
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

%typemap(in, numinputs=0) semanage_user_t **(semanage_user_t *temp=NULL) {
        $1 = &temp;
}

%typemap(argout) semanage_user_t ** {
        $result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
}

%typemap(argout) semanage_user_key_t ** {
        $result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
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

%typemap(in, numinputs=0) semanage_port_t **(semanage_port_t *temp=NULL) {
        $1 = &temp;
}

%typemap(argout) semanage_port_t ** {
        $result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
}

%typemap(argout) semanage_port_key_t ** {
        $result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
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

%typemap(in, numinputs=0) semanage_node_t **(semanage_node_t *temp=NULL) {
        $1 = &temp;
}

%typemap(argout) semanage_node_t ** {
        $result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
}


%typemap(argout) semanage_node_key_t ** {
        $result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
}

%typemap(in, numinputs=0) semanage_node_key_t **(semanage_node_key_t *temp=NULL) {
        $1 = &temp;
}

%include "semanageswig.i"
