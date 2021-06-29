/*
 * Copyright 2011 Tresys Technology, LLC. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *
 *    2. Redistributions in binary form must reproduce the above copyright notice,
 *       this list of conditions and the following disclaimer in the documentation
 *       and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY TRESYS TECHNOLOGY, LLC ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL TRESYS TECHNOLOGY, LLC OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation are those
 * of the authors and should not be interpreted as representing official policies,
 * either expressed or implied, of Tresys Technology, LLC.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <sys/stat.h>

#ifdef ANDROID
#include <cil/cil.h>
#else
#include <sepol/cil/cil.h>
#endif
#include <sepol/policydb.h>

enum write_ast_phase {
	WRITE_AST_PHASE_PARSE = 0,
	WRITE_AST_PHASE_BUILD,
	WRITE_AST_PHASE_RESOLVE,
};

static __attribute__((__noreturn__)) void usage(const char *prog)
{
	printf("Usage: %s [OPTION]... FILE...\n", prog);
	printf("\n");
	printf("Options:\n");
	printf("  -o, --output=<file>      write AST to <file>. (default: stdout)\n");
	printf("  -P, --preserve-tunables  treat tunables as booleans\n");
	printf("  -Q, --qualified-names    Allow names containing dots (qualified names).\n");
	printf("                           Blocks, blockinherits, blockabstracts, and\n");
	printf("                           in-statements will not be allowed.\n");
	printf("  -A, --ast-phase=<phase>  write AST of phase <phase>. Phase must be parse, \n");
	printf("                           build, or resolve. (default: resolve)\n");
	printf("  -v, --verbose            increment verbosity level\n");
	printf("  -h, --help               display usage information\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	int rc = SEPOL_ERR;
	FILE *file = NULL;
	char *buffer = NULL;
	struct stat filedata;
	uint32_t file_size;
	char *output = NULL;
	struct cil_db *db = NULL;
	int preserve_tunables = 0;
	int qualified_names = 0;
	enum write_ast_phase write_ast = WRITE_AST_PHASE_RESOLVE;
	int opt_char;
	int opt_index = 0;
	enum cil_log_level log_level = CIL_ERR;
	static struct option long_opts[] = {
		{"help", no_argument, 0, 'h'},
		{"verbose", no_argument, 0, 'v'},
		{"preserve-tunables", no_argument, 0, 'P'},
		{"qualified-names", no_argument, 0, 'Q'},
		{"output", required_argument, 0, 'o'},
		{"ast-phase", required_argument, 0, 'A'},
		{0, 0, 0, 0}
	};
	int i;

	while (1) {
		opt_char = getopt_long(argc, argv, "o:hvPQA:", long_opts, &opt_index);
		if (opt_char == -1) {
			break;
		}
		switch (opt_char) {
			case 'v':
				log_level++;
				break;
			case 'P':
				preserve_tunables = 1;
				break;
			case 'Q':
				qualified_names = 1;
				break;
			case 'o':
				output = strdup(optarg);
				break;
			case 'A':
				if (!strcasecmp(optarg, "parse")) {
					write_ast = WRITE_AST_PHASE_PARSE;
				} else if (!strcasecmp(optarg, "build")) {
					write_ast = WRITE_AST_PHASE_BUILD;
				} else if (!strcasecmp(optarg, "resolve")) {
					write_ast = WRITE_AST_PHASE_RESOLVE;
				} else {
					fprintf(stderr, "Invalid AST phase: %s\n", optarg);
					usage(argv[0]);
				}
				break;
			case 'h':
				usage(argv[0]);
			case '?':
				break;
			default:
				fprintf(stderr, "Unsupported option: %s\n", optarg);
				usage(argv[0]);
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "No cil files specified\n");
		usage(argv[0]);
	}

	cil_set_log_level(log_level);

	cil_db_init(&db);
	cil_set_preserve_tunables(db, preserve_tunables);
	cil_set_qualified_names(db, qualified_names);
	cil_set_attrs_expand_generated(db, 0);
	cil_set_attrs_expand_size(db, 0);

	for (i = optind; i < argc; i++) {
		file = fopen(argv[i], "r");
		if (!file) {
			fprintf(stderr, "Could not open file: %s\n", argv[i]);
			rc = SEPOL_ERR;
			goto exit;
		}
		rc = stat(argv[i], &filedata);
		if (rc == -1) {
			fprintf(stderr, "Could not stat file: %s\n", argv[i]);
			goto exit;
		}
		file_size = filedata.st_size;

		buffer = malloc(file_size);
		rc = fread(buffer, file_size, 1, file);
		if (rc != 1) {
			fprintf(stderr, "Failure reading file: %s\n", argv[i]);
			goto exit;
		}
		fclose(file);
		file = NULL;

		rc = cil_add_file(db, argv[i], buffer, file_size);
		if (rc != SEPOL_OK) {
			fprintf(stderr, "Failure adding %s\n", argv[i]);
			goto exit;
		}

		free(buffer);
		buffer = NULL;
	}

	if (output == NULL) {
		file = stdout;
	} else {
		file = fopen(output, "w");
		if (file == NULL) {
			fprintf(stderr, "Failure opening file %s for writing\n", output);
			rc = SEPOL_ERR;
			goto exit;
		}
	}

	switch (write_ast) {
	case WRITE_AST_PHASE_PARSE:
		rc = cil_write_parse_ast(file, db);
		break;
	case WRITE_AST_PHASE_BUILD:
		rc = cil_write_build_ast(file, db);
		break;
	case WRITE_AST_PHASE_RESOLVE:
		rc = cil_write_resolve_ast(file, db);
		break;
	}

	if (rc != SEPOL_OK) {
		fprintf(stderr, "Failed to write AST\n");
		goto exit;
	}

exit:
	if (file != NULL && file != stdin) {
		fclose(file);
	}
	free(buffer);
	free(output);
	cil_db_destroy(&db);
	return rc;
}
