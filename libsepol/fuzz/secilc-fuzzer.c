#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <sys/stat.h>

#include <sepol/cil/cil.h>
#include <sepol/policydb.h>

#ifndef VERBOSE
#define VERBOSE 0
#endif

#if !VERBOSE
static void log_handler(__attribute__((unused)) int lvl,
			__attribute__((unused)) const char *msg)
{
	/* be quiet */
}
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	enum cil_log_level log_level = CIL_ERR;
	struct sepol_policy_file *pf = NULL;
	FILE *dev_null = NULL;
	int target = SEPOL_TARGET_SELINUX;
	int disable_dontaudit = 0;
	int multiple_decls = 0;
	int disable_neverallow = 0;
	int preserve_tunables = 0;
	int policyvers = POLICYDB_VERSION_MAX;
	int mls = -1;
	int attrs_expand_generated = 0;
	struct cil_db *db = NULL;
	sepol_policydb_t *pdb = NULL;

	cil_set_log_level(log_level);
#if !VERBOSE
	cil_set_log_handler(log_handler);
#endif

	cil_db_init(&db);
	cil_set_disable_dontaudit(db, disable_dontaudit);
	cil_set_multiple_decls(db, multiple_decls);
	cil_set_disable_neverallow(db, disable_neverallow);
	cil_set_preserve_tunables(db, preserve_tunables);
	cil_set_mls(db, mls);
	cil_set_target_platform(db, target);
	cil_set_policy_version(db, policyvers);
	cil_set_attrs_expand_generated(db, attrs_expand_generated);

	if (cil_add_file(db, "fuzz", (const char *)data, size) != SEPOL_OK)
		goto exit;

	if (cil_compile(db) != SEPOL_OK)
		goto exit;

	if (cil_build_policydb(db, &pdb) != SEPOL_OK)
		goto exit;

	if (sepol_policydb_optimize(pdb) != SEPOL_OK)
		goto exit;

	dev_null = fopen("/dev/null", "w");
	if (dev_null == NULL)
		goto exit;

	if (sepol_policy_file_create(&pf) != 0)
		goto exit;

	sepol_policy_file_set_fp(pf, dev_null);

	if (sepol_policydb_write(pdb, pf) != 0)
		goto exit;
exit:
	if (dev_null != NULL)
		fclose(dev_null);

	cil_db_destroy(&db);
	sepol_policydb_free(pdb);
	sepol_policy_file_free(pf);
	return 0;
}

#ifdef DEFINEMAIN
#include <sys/mman.h>
#include <sys/stat.h>

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: %s fuzzer-input-file\n", argv[0]);
		exit(1);
	}

	FILE *fp = fopen(argv[1], "rb");
	if (!fp) {
		perror(argv[1]);
		exit(1);
	}

	struct stat sb;
	int rc;

	rc = fstat(fileno(fp), &sb);
	if (rc < 0) {
		perror("fstat");
		exit(1);
	}

	void *address = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE,
			     MAP_PRIVATE, fileno(fp), 0);
	if (address == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}

	return LLVMFuzzerTestOneInput(address, sb.st_size);
}
#endif
