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
extern void init_parser(int pass, const char *input_name);
extern int yyparse(void);
extern void yyrestart(FILE *);
extern int yylex_destroy(void);
extern queue_t id_queue;
extern unsigned int policydb_errors;
extern policydb_t *policydbp;
extern int mlspol;

int read_source_policy(policydb_t * p, const char *file, const char *progname)
{
	int rc = -1;

	yyin = fopen(file, "r");
	if (!yyin) {
		fprintf(stderr, "%s:  unable to open %s:  %s\n", progname, file, strerror(errno));
		return -1;
	}

	id_queue = queue_create();
	if (id_queue == NULL) {
		fprintf(stderr, "%s: out of memory!\n", progname);
		goto cleanup;
	}

	mlspol = p->mls;
	policydbp = p;
	policydbp->name = strdup(file);
	if (!policydbp->name) {
		fprintf(stderr, "%s: out of memory!\n", progname);
		goto cleanup;
	}

	init_parser(1, file);
	if (yyparse() || policydb_errors) {
		fprintf(stderr,
			"%s:  error(s) encountered while parsing configuration\n",
			progname);
		goto cleanup;
	}
	rewind(yyin);
	init_parser(2, file);
	yyrestart(yyin);
	if (yyparse() || policydb_errors) {
		fprintf(stderr,
			"%s:  error(s) encountered while parsing configuration\n",
			progname);
		goto cleanup;
	}

	rc = 0;

cleanup:
	queue_destroy(id_queue);
	fclose(yyin);
	yylex_destroy();

	return rc;
}
