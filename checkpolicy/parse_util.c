/*
 * Author: Karl MacMillan <kmacmillan@tresys.com>
 *
 * Copyright (C) 2006 Tresys Technology, LLC
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

#include "parse_util.h"
#include "queue.h"

/* these are defined in policy_parse.y and are needed for read_source_policy */
extern FILE *yyin;
extern void init_parser(int);
extern int yyparse(void);
extern void yyrestart(FILE *);
extern queue_t id_queue;
extern unsigned int policydb_errors;
extern unsigned long policydb_lineno;
extern policydb_t *policydbp;
extern int mlspol;
extern void set_source_file(const char *name);

int read_source_policy(policydb_t * p, const char *file, const char *progname)
{
	yyin = fopen(file, "r");
	if (!yyin) {
		fprintf(stderr, "%s:  unable to open %s\n", progname, file);
		return -1;
	}
	set_source_file(file);

	if ((id_queue = queue_create()) == NULL) {
		fprintf(stderr, "%s: out of memory!\n", progname);
		return -1;
	}

	policydbp = p;
	mlspol = p->mls;

	init_parser(1);
	if (yyparse() || policydb_errors) {
		fprintf(stderr,
			"%s:  error(s) encountered while parsing configuration\n",
			progname);
		return -1;
	}
	rewind(yyin);
	init_parser(2);
	set_source_file(file);
	yyrestart(yyin);
	if (yyparse() || policydb_errors) {
		fprintf(stderr,
			"%s:  error(s) encountered while parsing configuration\n",
			progname);
		return -1;
	}
	queue_destroy(id_queue);

	fclose(yyin);

	return 0;
}
