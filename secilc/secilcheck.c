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
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

#ifdef ANDROID
#include <cil/cil.h>
#else
#include <sepol/cil/cil.h>
#endif
#include <sepol/policydb.h>
#include <sepol/kernel_to_cil.h>

static int get_binary_policy_db(const char *filename, sepol_policydb_t *pdb)
{
	int fd;
	struct stat sb;
	void *map = NULL;
	sepol_policy_file_t *pf = NULL;
	int rc = SEPOL_ERR;

	/* Read binary policy */
	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Could not open file: %s\n", filename);
		goto exit;
	}
	if (fstat(fd, &sb) < 0) {
		fprintf(stderr, "Could not stat file: %s\n", filename);
		goto exit;
	}
	map = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd,
		   0);
	if (map == MAP_FAILED) {
		fprintf(stderr, "Could not map file: %s\n", filename);
		goto exit;
	}

	if (sepol_policy_file_create(&pf) < 0) {
		fprintf(stderr, "Out of memory");
		goto exit;
	}
	sepol_policy_file_set_mem(pf, map, sb.st_size);

	if (sepol_policydb_read(pdb, pf) < 0) {
		fprintf(stderr, "Error reading binary policy: %s\n", filename);
		rc = SEPOL_ERR;
		goto exit;
	}

	rc = SEPOL_OK;

exit:
	if (fd >= 0)
		close(fd);
	if (map)
		munmap(map, sb.st_size);
	sepol_policy_file_free(pf);
	return rc;
}

static int add_decls_to_cil(const char *filename, sepol_policydb_t *pdb,
			    struct cil_db *db)
{
	FILE *cfp = NULL;
	char *cptr = NULL;
	size_t csize;
	int rc = SEPOL_ERR;

	cfp = open_memstream(&cptr, &csize);
	if (!cfp) {
		fprintf(stderr,
			"Failed to open dynamic memory buffer stream\n");
		goto exit;
	}

	if (sepol_kernel_policydb_decls_to_cil(cfp, &pdb->p) < 0) {
		fprintf(stderr, "Failed to convert binary policy to CIL\n");
		goto exit;
	}

	if (fflush(cfp) < 0) {
		fprintf(stderr, "Failed to flush CIL memory buffer stream\n");
		goto exit;
	}

	/* Add to CIL db */
	if (cil_add_file(db, filename, cptr, csize) < 0) {
		fprintf(stderr, "Failed to add binary policy file: %s\n",
			filename);
		goto exit;
	}

	rc = 0;

exit:
	if (cfp)
		fclose(cfp);
	if (cptr)
		free(cptr);
	return rc;
}

static int add_cil_file(const char *filename, struct cil_db *cdb)
{
	FILE *file;
	struct stat filedata;
	char *buffer = NULL;
	size_t file_size;
	int rc = -1;

	file = fopen(filename, "r");
	if (!file) {
		fprintf(stderr, "Could not open file: %s\n", filename);
		goto exit;
	}
	if (stat(filename, &filedata) < 0) {
		fprintf(stderr, "Could not stat file: %s\n", filename);
		goto exit;
	}
	file_size = filedata.st_size;

	if (!file_size) {
		fclose(file);
		rc = 0;
		goto exit;
	}

	buffer = malloc(file_size);
	if (!buffer) {
		fprintf(stderr, "Out of memory\n");
		goto exit;
	}

	if (fread(buffer, file_size, 1, file) != 1) {
		fprintf(stderr, "Failure reading file: %s\n", filename);
		goto exit;
	}

	if (cil_add_file(cdb, filename, buffer, file_size) < 0) {
		fprintf(stderr, "Failure adding %s\n", filename);
		goto exit;
	}

	rc = 0;

exit:
	if (file)
		fclose(file);
	if (buffer)
		free(buffer);
	return rc;
}

static __attribute__((__noreturn__)) void usage(const char *prog)
{
	printf("Usage: %s [OPTION]... BIN_POLICY CIL_NEVERALLOW_FILE1...\n",
	       prog);
	printf("\n");
	printf("Options:\n");
	printf("  -Q, --qualified-names          Allow names containing dots (qualified names).\n");
	printf("                                 Blocks, blockinherits, blockabstracts, and\n");
	printf("                                 in-statements will not be allowed.\n");
	printf("  -m, --multiple-decls           allow some statements to be re-declared\n");
	printf("  -v, --verbose                  increment verbosity level\n");
	printf("  -h, --help                     display usage information\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	int rc = SEPOL_ERR;
	sepol_policydb_t *pdb = NULL;
	int violation = 0;
	struct cil_db *db = NULL;
	int multiple_decls = 0;
	int qualified_names = 0;
	int opt_char;
	int opt_index = 0;
	enum cil_log_level log_level = CIL_ERR;
	static struct option long_opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "multiple-decls", no_argument, NULL, 'm' },
		{ "qualified-names", no_argument, NULL, 'Q' },
		{ NULL, 0, NULL, 0 }
	};

	while (1) {
		opt_char =
			getopt_long(argc, argv, "hvQm", long_opts, &opt_index);
		if (opt_char == -1) {
			break;
		}
		switch (opt_char) {
		case 'v':
			log_level++;
			break;
		case 'm':
			multiple_decls = 1;
			break;
		case 'Q':
			qualified_names = 1;
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

	if (argc < optind + 2) {
		fprintf(stderr, "Not enough files specified\n");
		usage(argv[0]);
	}

	cil_set_log_level(log_level);

	cil_db_init(&db);
	cil_set_multiple_decls(db, multiple_decls);
	cil_set_qualified_names(db, qualified_names);

	if (sepol_policydb_create(&pdb) < 0) {
		fprintf(stderr, "Out of memory\n");
		goto exit;
	}
	if (get_binary_policy_db(argv[optind], pdb) < 0) {
		fprintf(stderr, "Failed to get binary policy db\n");
		rc = SEPOL_ERR;
		goto exit;
	}
	if (add_decls_to_cil(argv[optind], pdb, db) < 0) {
		fprintf(stderr, "Failed to convert decls to CIL\n");
		rc = SEPOL_ERR;
		goto exit;
	}
	optind++;

	do {
		if (add_cil_file(argv[optind], db) < 0) {
			fprintf(stderr,
				"Failed to add cil file to CIL files\n");
			rc = SEPOL_ERR;
			goto exit;
		}
		optind++;
	} while (optind < argc);

	rc = cil_compile(db);
	if (rc != SEPOL_OK) {
		fprintf(stderr, "Failed to compile cildb: %d\n", rc);
		goto exit;
	}

	rc = cil_check_neverallows_against_pdb(db, &pdb->p, &violation);
	if (rc != SEPOL_OK) {
		fprintf(stderr, "Failed to complete neverallow checking\n");
		goto exit;
	}
	if (violation == 1) {
		fprintf(stderr, "There was a neverallow violation\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	rc = SEPOL_OK;

exit:
	cil_db_destroy(&db);
	sepol_policydb_free(pdb);
	return rc;
}
