/* Author: Dan Walsh
   Based on selinuxswig_python.i by James Athey
 */

%module selinux
%{
	#include "selinux/selinux.h"
%}

/* return a sid along with the result */
%typemap(argout) (security_id_t * sid) {
	if (*$1) {
                %append_output(SWIG_NewPointerObj(*$1, $descriptor(security_id_t), 0));
	} 
}

%typemap(in,numinputs=0) security_id_t *(security_id_t temp) {
  $1 = &temp;
}

%typemap(in,noblock=1,numinputs=0) char ** (char * temp = 0) {
	$1 = &temp;
}
%typemap(freearg,match="in") char ** "";
%typemap(argout,noblock=1) char ** {
	if (*$1) {
		%append_output(SWIG_FromCharPtr(*$1));
		freecon(*$1);
	}
}

%typemap(in,noblock=1,numinputs=0) char ** (char * temp = 0) {
	$1 = &temp;
}
%typemap(freearg,match="in") char ** "";
%typemap(argout,noblock=1) char ** {
	if (*$1) {
		%append_output(SWIG_FromCharPtr(*$1));
		free(*$1);
	}
}

%typemap(freearg,match="in") char * const [] {
	int i = 0;
	while($1[i]) {
		free($1[i]);
		i++;
	}
	free($1);
}

%include "selinuxswig.i"
