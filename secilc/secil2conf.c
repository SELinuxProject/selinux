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

static __attribute__((__noreturn__)) void usage(const char *prog)
{
	printf("Usage: %s [OPTION]... FILE...\n", prog);
	printf("\n");
	printf("Options:\n");
	printf("  -o, --output=<file>            write policy.conf to <file>\n");
	printf("                                 (default: policy.conf)\n");
	printf("  -M, --mls true|false           write an mls policy. Must be true or false.\n");
	printf("                                 This will override the (mls boolean) statement\n");
	printf("                                 if present in the policy\n");
	printf("  -P, --preserve-tunables        treat tunables as booleans\n");
	printf("  -v, --verbose                  increment verbosity level\n");
	printf("  -h, --help                     display usage information\n");
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
	int mls = -1;
	int preserve_tunables = 0;
	int opt_char;
	int opt_index = 0;
	enum cil_log_level log_level = CIL_ERR;
	static struct option long_opts[] = {
		{"help", no_argument, 0, 'h'},
		{"verbose", no_argument, 0, 'v'},
		{"mls", required_argument, 0, 'M'},
		{"preserve-tunables", no_argument, 0, 'P'},
		{"output", required_argument, 0, 'o'},
		{0, 0, 0, 0}
	};
	int i;

	while (1) {
		opt_char = getopt_long(argc, argv, "o:hvM:P", long_opts, &opt_index);
		if (opt_char == -1) {
			break;
		}
		switch (opt_char) {
			case 'v':
				log_level++;
				break;
			case 'M':
				if (!strcasecmp(optarg, "true") || !strcasecmp(optarg, "1")) {
					mls = 1;
				} else if (!strcasecmp(optarg, "false") || !strcasecmp(optarg, "0")) {
					mls = 0;
				} else {
					usage(argv[0]);
				}
				break;
			case 'P':
				preserve_tunables = 1;
				break;
			case 'o':
				output = strdup(optarg);
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
	cil_set_mls(db, mls);
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

	rc = cil_compile(db);
	if (rc != SEPOL_OK) {
		fprintf(stderr, "Failed to compile cildb: %d\n", rc);
		goto exit;
	}

	if (output == NULL) {
		file = fopen("policy.conf", "w");
	} else {
		file = fopen(output, "w");
	}
	if (file == NULL) {
		fprintf(stderr, "Failure opening policy.conf file for writing\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	cil_write_policy_conf(file, db);

	fclose(file);
	file = NULL;
	rc = SEPOL_OK;

exit:
	if (file != NULL) {
		fclose(file);
	}
	free(buffer);
	free(output);
	cil_db_destroy(&db);
	return rc;
}
