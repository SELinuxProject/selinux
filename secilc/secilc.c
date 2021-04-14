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
	printf("  -o, --output=<file>            write binary policy to <file>\n");
	printf("                                 (default: policy.<version>)\n");
	printf("  -f, --filecontext=<file>       write file contexts to <file>\n");
	printf("                                 (default: file_contexts)\n");
	printf("  -t, --target=<type>            specify target architecture. may be selinux or\n");
	printf("                                 xen. (default: selinux)\n");
	printf("  -M, --mls true|false           build an mls policy. Must be true or false.\n");
	printf("                                 This will override the (mls boolean) statement\n");
	printf("                                 if present in the policy\n");
	printf("  -c, --policyvers=<version>     build a binary policy with a given <version>\n");
	printf("                                 (default: %i)\n", POLICYDB_VERSION_MAX);
	printf("  -U, --handle-unknown=<action>  how to handle unknown classes or permissions.\n");
	printf("                                 may be deny, allow, or reject. (default: deny)\n");
	printf("                                 This will override the (handleunknown action)\n");
	printf("                                 statement if present in the policy\n");
	printf("  -D, --disable-dontaudit        do not add dontaudit rules to the binary policy\n");
	printf("  -P, --preserve-tunables        treat tunables as booleans\n");
	printf("  -m, --multiple-decls           allow some statements to be re-declared\n");
	printf("  -N, --disable-neverallow       do not check neverallow rules\n");
	printf("  -G, --expand-generated         Expand and remove auto-generated attributes\n");
	printf("  -X, --expand-size <SIZE>       Expand type attributes with fewer than <SIZE>\n");
	printf("                                 members.\n");
	printf("  -O, --optimize                 optimize final policy\n");
	printf("  -v, --verbose                  increment verbosity level\n");
	printf("  -h, --help                     display usage information\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	int rc = SEPOL_ERR;
	sepol_policydb_t *pdb = NULL;
	struct sepol_policy_file *pf = NULL;
	FILE *binary = NULL;
	FILE *file_contexts;
	FILE *file = NULL;
	char *buffer = NULL;
	struct stat filedata;
	uint32_t file_size;
	char *output = NULL;
	char *filecontexts = NULL;
	struct cil_db *db = NULL;
	int target = SEPOL_TARGET_SELINUX;
	int mls = -1;
	int disable_dontaudit = 0;
	int multiple_decls = 0;
	int disable_neverallow = 0;
	int preserve_tunables = 0;
	int handle_unknown = -1;
	int policyvers = POLICYDB_VERSION_MAX;
	int attrs_expand_generated = 0;
	int attrs_expand_size = -1;
	int optimize = 0;
	int opt_char;
	int opt_index = 0;
	char *fc_buf = NULL;
	size_t fc_size;
	enum cil_log_level log_level = CIL_ERR;
	static struct option long_opts[] = {
		{"help", no_argument, 0, 'h'},
		{"verbose", no_argument, 0, 'v'},
		{"target", required_argument, 0, 't'},
		{"mls", required_argument, 0, 'M'},
		{"policyversion", required_argument, 0, 'c'},
		{"handle-unknown", required_argument, 0, 'U'},
		{"disable-dontaudit", no_argument, 0, 'D'},
		{"multiple-decls", no_argument, 0, 'm'},
		{"disable-neverallow", no_argument, 0, 'N'},
		{"preserve-tunables", no_argument, 0, 'P'},
		{"output", required_argument, 0, 'o'},
		{"filecontexts", required_argument, 0, 'f'},
		{"expand-generated", no_argument, 0, 'G'},
		{"expand-size", required_argument, 0, 'X'},
		{"optimize", no_argument, 0, 'O'},
		{0, 0, 0, 0}
	};
	int i;

	while (1) {
		opt_char = getopt_long(argc, argv, "o:f:U:hvt:M:PDmNOc:GX:n", long_opts, &opt_index);
		if (opt_char == -1) {
			break;
		}
		switch (opt_char) {
			case 'v':
				log_level++;
				break;
			case 't':
				if (!strcmp(optarg, "selinux")) {
					target = SEPOL_TARGET_SELINUX;
				} else if (!strcmp(optarg, "xen")) {
					target = SEPOL_TARGET_XEN;
				} else {
					fprintf(stderr, "Unknown target: %s\n", optarg);
					usage(argv[0]);
				}
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
			case 'c': {
				char *endptr = NULL;
				errno = 0;
				policyvers = strtol(optarg, &endptr, 10);
				if (errno != 0 || endptr == optarg || *endptr != '\0') {
					fprintf(stderr, "Bad policy version: %s\n", optarg);
					usage(argv[0]);
				}
				if (policyvers > POLICYDB_VERSION_MAX || policyvers < POLICYDB_VERSION_MIN) {
					fprintf(stderr, "Policy version must be between %d and %d\n",
					       POLICYDB_VERSION_MIN, POLICYDB_VERSION_MAX);
					usage(argv[0]);
				}
				break;
			}
			case 'U':
				if (!strcasecmp(optarg, "deny")) {
					handle_unknown = SEPOL_DENY_UNKNOWN;
				} else if (!strcasecmp(optarg, "allow")) {
					handle_unknown = SEPOL_ALLOW_UNKNOWN;
				} else if (!strcasecmp(optarg, "reject")) {
					handle_unknown = SEPOL_REJECT_UNKNOWN;
				} else {
					usage(argv[0]);
				}
				break;
			case 'D':
				disable_dontaudit = 1;
				break;
			case 'm':
				multiple_decls = 1;
				break;
			case 'N':
				disable_neverallow = 1;
				break;
			case 'P':
				preserve_tunables = 1;
				break;
			case 'o':
				output = strdup(optarg);
				break;
			case 'f':
				filecontexts = strdup(optarg);
				break;
			case 'G':
				attrs_expand_generated = 1;
				break;
			case 'X': {
				char *endptr = NULL;
				errno = 0;
				attrs_expand_size = strtol(optarg, &endptr, 10);
				if (errno != 0 || endptr == optarg || *endptr != '\0') {
					fprintf(stderr, "Bad attribute expand size: %s\n", optarg);
					usage(argv[0]);
				}

				if (attrs_expand_size < 0) {
					fprintf(stderr, "Attribute expand size must be > 0\n");
					usage(argv[0]);
				}
				break;
			}
			case 'O':
				optimize = 1;
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
	cil_set_disable_dontaudit(db, disable_dontaudit);
	cil_set_multiple_decls(db, multiple_decls);
	cil_set_disable_neverallow(db, disable_neverallow);
	cil_set_preserve_tunables(db, preserve_tunables);
	if (handle_unknown != -1) {
		rc = cil_set_handle_unknown(db, handle_unknown);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	cil_set_mls(db, mls);
	cil_set_target_platform(db, target);
	cil_set_policy_version(db, policyvers);
	cil_set_attrs_expand_generated(db, attrs_expand_generated);
	if (attrs_expand_size >= 0) {
		cil_set_attrs_expand_size(db, (unsigned)attrs_expand_size);
	}

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
			rc = SEPOL_ERR;
			goto exit;
		}
		file_size = filedata.st_size;

		if (!file_size) {
			fclose(file);
			file = NULL;
			continue;
		}

		buffer = malloc(file_size);
		rc = fread(buffer, file_size, 1, file);
		if (rc != 1) {
			fprintf(stderr, "Failure reading file: %s\n", argv[i]);
			rc = SEPOL_ERR;
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

	rc = cil_build_policydb(db, &pdb);
	if (rc != SEPOL_OK) {
		fprintf(stderr, "Failed to build policydb\n");
		goto exit;
	}

	if (optimize) {
		rc = sepol_policydb_optimize(pdb);
		if (rc != SEPOL_OK) {
			fprintf(stderr, "Failed to optimize policydb\n");
			goto exit;
		}
	}

	if (output == NULL) {
		int size = snprintf(NULL, 0, "policy.%d", policyvers);
		output = malloc((size + 1) * sizeof(char));
		if (output == NULL) {
			fprintf(stderr, "Failed to create output filename\n");
			rc = SEPOL_ERR;
			goto exit;
		}
		if (snprintf(output, size + 1, "policy.%d", policyvers) != size) {
			fprintf(stderr, "Failed to create output filename\n");
			rc = SEPOL_ERR;
			goto exit;
		}
	}

	binary = fopen(output, "w");
	if (binary == NULL) {
		fprintf(stderr, "Failure opening binary file for writing\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	rc = sepol_policy_file_create(&pf);
	if (rc != 0) {
		fprintf(stderr, "Failed to create policy file: %d\n", rc);
		goto exit;
	}

	sepol_policy_file_set_fp(pf, binary);

	rc = sepol_policydb_write(pdb, pf);
	if (rc != 0) {
		fprintf(stderr, "Failed to write binary policy: %d\n", rc);
		goto exit;
	}

	fclose(binary);
	binary = NULL;

	rc = cil_filecons_to_string(db, &fc_buf, &fc_size);
	if (rc != SEPOL_OK) {
		fprintf(stderr, "Failed to get file context data\n");
		goto exit;
	}

	if (filecontexts == NULL) {
		file_contexts = fopen("file_contexts", "w+");
	} else {
		file_contexts = fopen(filecontexts, "w+");
	}

	if (file_contexts == NULL) {
		fprintf(stderr, "Failed to open file_contexts file\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	if (fwrite(fc_buf, sizeof(char), fc_size, file_contexts) != fc_size) {
		fprintf(stderr, "Failed to write file_contexts file\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	fclose(file_contexts);
	file_contexts = NULL;

	rc = SEPOL_OK;

exit:
	if (binary != NULL) {
		fclose(binary);
	}
	if (file != NULL) {
		fclose(file);
	}
	free(buffer);
	free(output);
	free(filecontexts);
	cil_db_destroy(&db);
	sepol_policydb_free(pdb);
	sepol_policy_file_free(pf);
	free(fc_buf);
	return rc;
}
