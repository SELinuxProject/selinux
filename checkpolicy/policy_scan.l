
/* 
 * Author : Stephen Smalley, <sds@tycho.nsa.gov>
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
int yywarn(const char *msg);

void set_source_file(const char *name);

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
\n.*				{ strncpy(linebuf[lno], yytext+1, 255);
                                  linebuf[lno][254] = 0;
                                  lno = 1 - lno; 
                                  policydb_lineno++;
				  source_lineno++;
                                  yyless(1); }
CLONE |
clone				{ return(CLONE); }
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
"/"[^ \n\r\t\f]*	        { return(PATH); }
\""/"[^\"\n]*\" 		{ return(QPATH); }
\"[^"/"\"\n]+\"	{ return(FILENAME); }
{letter}({alnum}|[_\-])*([\.]?({alnum}|[_\-]))*	{ return(IDENTIFIER); }
{digit}+|0x{hexval}+            { return(NUMBER); }
{alnum}*{letter}{alnum}*        { return(FILESYSTEM); }
{digit}{1,3}(\.{digit}{1,3}){3}    { return(IPV4_ADDR); }
{hexval}{0,4}":"{hexval}{0,4}":"({hexval}|[:.])*  { return(IPV6_ADDR); }
{digit}+(\.({alnum}|[_.])*)?    { return(VERSION_IDENTIFIER); }
#line[ ]1[ ]\"[^\n]*\"		{ set_source_file(yytext+9); }
#line[ ]{digit}+	        { source_lineno = atoi(yytext+6)-1; }
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
.                               { yywarn("unrecognized character");}
%%
int yyerror(const char *msg)
{
	if (source_file[0])
		fprintf(stderr, "%s:%ld:",
			source_file, source_lineno);
	else
		fprintf(stderr, "(unknown source)::");
	fprintf(stderr, "ERROR '%s' at token '%s' on line %ld:\n%s\n%s\n",
			msg,
			yytext,
			policydb_lineno,
			linebuf[0], linebuf[1]);
	policydb_errors++;
	return -1;
}

int yywarn(const char *msg)
{
	if (source_file[0])
		fprintf(stderr, "%s:%ld:",
			source_file, source_lineno);
	else
		fprintf(stderr, "(unknown source)::");
	fprintf(stderr, "WARNING '%s' at token '%s' on line %ld:\n%s\n%s\n",
			msg,
			yytext,
			policydb_lineno,
			linebuf[0], linebuf[1]);
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
