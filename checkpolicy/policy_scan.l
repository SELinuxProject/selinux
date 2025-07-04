
/* 
 * Author : Stephen Smalley, <stephen.smalley.work@gmail.com>
 */

/* Updated: David Caplan, <dac@tresys.com>
 *
 * 	Added conditional policy language extensions
 *
 *          Jason Tang    <jtang@tresys.com>
 *
 *	Added support for binary policy modules
 *
 * Copyright (C) 2003-5 Tresys Technology, LLC
 * Copyright (C) 2017 Mellanox Technologies Inc.
 *	This program is free software; you can redistribute it and/or modify
 *  	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, version 2.
 */

/* FLASK */

%{
#include <sys/types.h>
#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>

typedef int (* require_func_t)(void);

#ifdef ANDROID
#include "policy_parse.h"
#else
#include "y.tab.h"
#endif

static char linebuf[2][255];
static unsigned int lno = 0;
int werror = 0;
int yyerror(const char *msg);
int yywarn(const char *msg);

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
/*
 * Version that does not exit, like yy_fatal_error(),
 * since fuzz targets must not call exit().
 */
#include <setjmp.h>
extern jmp_buf fuzzing_pre_parse_stack_state;
void yyfatal(const char *msg)
{
	yyerror(msg);
	longjmp(fuzzing_pre_parse_stack_state, 1);
}
#define YY_FATAL_ERROR(msg) yyfatal(msg)
#endif

void set_source_file(const char *name);
static void set_source_line_and_file(const char *line);

char source_file[PATH_MAX];
unsigned long source_lineno = 1;

unsigned long policydb_lineno = 1;

unsigned int policydb_errors = 0;
%}

%option noinput nounput noyywrap

%array
letter  [A-Za-z]
digit   [0-9]
alnum   [a-zA-Z0-9]
hexval	[0-9A-Fa-f]

%%
\n.*				{
#if defined(__GNUC__) && __GNUC__ >= 8
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-truncation"
#endif
				  strncpy(linebuf[lno], yytext+1, 255);
#if defined(__GNUC__) && __GNUC__ >= 8
#pragma GCC diagnostic pop
#endif
				  linebuf[lno][254] = 0;
				  lno = 1 - lno;
				  policydb_lineno++;
				  if (source_lineno == ULONG_MAX)
				      yywarn("source line number overflow");
				  else
				      source_lineno++;
				  yyless(1);
				}
COMMON |
common				{ return(COMMON); }
CLASS |
class				{ return(CLASS); }
CONSTRAIN |
constrain			{ return(CONSTRAIN); }
VALIDATETRANS |
validatetrans			{ return(VALIDATETRANS); }
INHERITS |
inherits			{ return(INHERITS); }
SID |
sid				{ return(SID); }
ROLE |
role				{ return(ROLE); }
ROLES |
roles				{ return(ROLES); }
ROLEATTRIBUTE |
roleattribute			{ return(ROLEATTRIBUTE);}
ATTRIBUTE_ROLE |
attribute_role			{ return(ATTRIBUTE_ROLE);}
TYPES |
types				{ return(TYPES); }
TYPEALIAS |
typealias			{ return(TYPEALIAS); }
TYPEATTRIBUTE |
typeattribute			{ return(TYPEATTRIBUTE); }
TYPEBOUNDS |
typebounds			{ return(TYPEBOUNDS); }
TYPE |
type				{ return(TYPE); }
BOOL |
bool                            { return(BOOL); }
TUNABLE |
tunable				{ return(TUNABLE); }
IF |
if				{ return(IF); }
ELSE |
else				{ return(ELSE); }
ALIAS |
alias				{ return(ALIAS); }
ATTRIBUTE |
attribute			{ return(ATTRIBUTE); }
EXPANDATTRIBUTE |
expandattribute                 { return(EXPANDATTRIBUTE); }
TYPE_TRANSITION |
type_transition			{ return(TYPE_TRANSITION); }
TYPE_MEMBER |
type_member			{ return(TYPE_MEMBER); }
TYPE_CHANGE |
type_change			{ return(TYPE_CHANGE); }
ROLE_TRANSITION |
role_transition			{ return(ROLE_TRANSITION); }
RANGE_TRANSITION |
range_transition		{ return(RANGE_TRANSITION); }
SENSITIVITY |
sensitivity			{ return(SENSITIVITY); }
DOMINANCE |
dominance			{ return(DOMINANCE); }
CATEGORY |
category			{ return(CATEGORY); }
LEVEL |
level				{ return(LEVEL); }
RANGE |
range				{ return(RANGE); }
MLSCONSTRAIN |
mlsconstrain			{ return(MLSCONSTRAIN); }
MLSVALIDATETRANS |
mlsvalidatetrans		{ return(MLSVALIDATETRANS); }
USER |
user				{ return(USER); }
NEVERALLOW |
neverallow		        { return(NEVERALLOW); }
ALLOW |
allow			        { return(ALLOW); }
AUDITALLOW |
auditallow		        { return(AUDITALLOW); }
AUDITDENY |
auditdeny		        { return(AUDITDENY); }
DONTAUDIT |
dontaudit                       { return(DONTAUDIT); }
ALLOWXPERM |
allowxperm			{ return(ALLOWXPERM); }
AUDITALLOWXPERM |
auditallowxperm			{ return(AUDITALLOWXPERM); }
DONTAUDITXPERM |
dontauditxperm			{ return(DONTAUDITXPERM); }
NEVERALLOWXPERM |
neverallowxperm			{ return(NEVERALLOWXPERM); }
SOURCE |
source			        { return(SOURCE); }
TARGET |
target			        { return(TARGET); }
SAMEUSER |
sameuser			{ return(SAMEUSER);}
module|MODULE                   { return(MODULE); }
require|REQUIRE                 { return(REQUIRE); }
optional|OPTIONAL               { return(OPTIONAL); }
OR |
or     			        { return(OR);}
AND |
and				{ return(AND);}
NOT |
not				{ return(NOT);}
xor |
XOR                             { return(XOR); }
eq |
EQ				{ return(EQUALS);}
true |
TRUE                            { return(CTRUE); } 
false |
FALSE                           { return(CFALSE); } 
dom |
DOM				{ return(DOM);}
domby |
DOMBY				{ return(DOMBY);}
INCOMP |
incomp				{ return(INCOMP);}
fscon |
FSCON                           { return(FSCON);}
ibpkeycon |
IBPKEYCON			{ return(IBPKEYCON);}
ibendportcon |
IBENDPORTCON			{ return(IBENDPORTCON);}
portcon |
PORTCON				{ return(PORTCON);}
netifcon |                     
NETIFCON			{ return(NETIFCON);}
nodecon |                     
NODECON				{ return(NODECON);}
pirqcon |
PIRQCON  		        { return(PIRQCON);}
iomemcon |
IOMEMCON            		{ return(IOMEMCON);}
ioportcon |
IOPORTCON           		{ return(IOPORTCON);}
pcidevicecon |
PCIDEVICECON           		{ return(PCIDEVICECON);}
devicetreecon |
DEVICETREECON           	{ return(DEVICETREECON);}
fs_use_xattr |
FS_USE_XATTR			{ return(FSUSEXATTR);}
fs_use_task |
FS_USE_TASK                     { return(FSUSETASK);}
fs_use_trans |
FS_USE_TRANS                    { return(FSUSETRANS);}
genfscon |
GENFSCON                        { return(GENFSCON);}
r1 |
R1				{ return(R1); }
r2 |
R2				{ return(R2); }
r3 |
R3				{ return(R3); }
u1 |
U1				{ return(U1); }
u2 |
U2				{ return(U2); }
u3 |
U3				{ return(U3); }
t1 |
T1				{ return(T1); }
t2 |
T2				{ return(T2); }
t3 |
T3				{ return(T3); }
l1 |
L1				{ return(L1); }
l2 |
L2				{ return(L2); }
h1 |
H1				{ return(H1); }
h2 |
H2				{ return(H2); }
policycap |
POLICYCAP			{ return(POLICYCAP); }
permissive |
PERMISSIVE			{ return(PERMISSIVE); }
neveraudit |
NEVERAUDIT			{ return(NEVERAUDIT); }
default_user |
DEFAULT_USER			{ return(DEFAULT_USER); }
default_role |
DEFAULT_ROLE			{ return(DEFAULT_ROLE); }
default_type |
DEFAULT_TYPE			{ return(DEFAULT_TYPE); }
default_range |
DEFAULT_RANGE			{ return(DEFAULT_RANGE); }
low-high |
LOW-HIGH			{ return(LOW_HIGH); }
high |
HIGH				{ return(HIGH); }
low |
LOW				{ return(LOW); }
glblub |
GLBLUB				{ return(GLBLUB); }
"/"[^ \n\r\t\f]*	        { return(PATH); }
\""/"[^\"\n]*\" 		{ return(QPATH); }
\"[^"/"\"\n]+\"	{ return(FILENAME); }
{letter}({alnum}|[_\-])*([\.]?({alnum}|[_\-]))*	{ return(IDENTIFIER); }
{digit}+|0x{hexval}+            { return(NUMBER); }
{alnum}*{letter}{alnum}*        { return(FILESYSTEM); }
{digit}{1,3}(\.{digit}{1,3}){3}"/"{digit}{1,2}	{ return(IPV4_CIDR); }
{digit}{1,3}(\.{digit}{1,3}){3}    { return(IPV4_ADDR); }
{hexval}{0,4}":"{hexval}{0,4}":"({hexval}|[:.])*  { return(IPV6_ADDR); }
{hexval}{0,4}":"{hexval}{0,4}":"({hexval}|[:.])*"/"{digit}{1,3}	{ return(IPV6_CIDR); }
{digit}+(\.({alnum}|[_.])*)?    { return(VERSION_IDENTIFIER); }
({alnum}({alnum}|[\*\?_]){0,15}|[\*\?]({alnum}|[\*\?_]){1,15})	{ return(NETIFNAME); }
#line[ ]{digit}+[ ]\"[^\n]*\"	{ set_source_line_and_file(yytext+6); }
#line[ ]{digit}+	        {
				  errno = 0;
				  source_lineno = strtoul(yytext+6, NULL, 10) - 1;
				  if (errno) {
				    yywarn("source line number too big");
				  }
				}
#[^\n]*                         { /* delete comments */ }
[ \t\f]+			{ /* delete whitespace */ }
"==" 				{ return(EQUALS); }
"!="				{ return (NOTEQUAL); }
"&&"				{ return (AND); }
"||"				{ return (OR); }
"!"				{ return (NOT); }
"^"                             { return (XOR); }
"," |
":" |
";" |
"(" | 
")" |
"{" | 
"}" |
"[" |
"-" |
"." |
"]" |
"~" |
"*"				{ return(yytext[0]); } 
.                               { yyerror("unrecognized character");
/* Available since bison 3.6, avoids duplicate error message */
#ifdef YYerror
				  return YYerror;
#else
				  return INVALID_CHAR;
#endif
				}
%%
int yyerror(const char *msg)
{
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
	const char *token;
	char buf[8];

	if (isprint((unsigned char)yytext[0])) {
		token = yytext;
	} else {
		snprintf(buf, sizeof(buf), "%#x", yytext[0]);
		token = buf;
	}

	if (source_file[0])
		fprintf(stderr, "%s:%lu:",
			source_file, source_lineno);
	else
		fprintf(stderr, "(unknown source)::");
	fprintf(stderr, "ERROR '%s' at token '%s' on line %lu:\n%s\n%s\n",
			msg,
			token,
			policydb_lineno,
			linebuf[0], linebuf[1]);
#else
	(void)msg;
#endif

	policydb_errors++;
	return -1;
}

int yywarn(const char *msg)
{
	if (werror)
		return yyerror(msg);

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
	if (source_file[0])
		fprintf(stderr, "%s:%lu:",
			source_file, source_lineno);
	else
		fprintf(stderr, "(unknown source)::");
	fprintf(stderr, "WARNING '%s' at token '%s' on line %lu:\n%s\n%s\n",
			msg,
			yytext,
			policydb_lineno,
			linebuf[0], linebuf[1]);
#endif

	return 0;
}

void set_source_file(const char *name)
{
	source_lineno = 1;
	strncpy(source_file, name, sizeof(source_file)-1); 
	source_file[sizeof(source_file)-1] = '\0';
	if (strlen(source_file) && source_file[strlen(source_file)-1] == '"')
		source_file[strlen(source_file)-1] = '\0';
}

void set_source_line_and_file(const char *line)
{
	char *name;
	unsigned long lineno;
	errno = 0;
	lineno = strtoul(line, &name, 10) - 1;
	if (errno) {
		yywarn("source line number too big");
	}
	set_source_file(name + 2 /* skip a space and a quote */ );

	/*
	 * set_source_file sets source_lineno to 1.
	 * Assign source_lineno after calling set_source_file.
	 */
	source_lineno = lineno;
}
