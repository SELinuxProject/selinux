#include <sepol/debug.h>
#include <sepol/kernel_to_cil.h>
#include <sepol/kernel_to_conf.h>
#include <sepol/policydb/policydb.h>

extern int policydb_validate(sepol_handle_t *handle, const policydb_t *p);

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static int write_binary_policy(policydb_t *p, FILE *outfp)
{
	struct policy_file pf;

	policy_file_init(&pf);
	pf.type = PF_USE_STDIO;
	pf.fp = outfp;
	return policydb_write(p, &pf);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	policydb_t policydb = {};
	sidtab_t sidtab = {};
	struct policy_file pf;
	FILE *devnull = NULL;

	sepol_debug(0);

	policy_file_init(&pf);
	pf.type = PF_USE_MEMORY;
	pf.data = (char *) data;
	pf.len = size;

	if (policydb_init(&policydb))
		goto exit;

	if (policydb_read(&policydb, &pf, /*verbose=*/0))
		goto exit;

	if (policydb_load_isids(&policydb, &sidtab))
		goto exit;

	if (policydb.policy_type == POLICY_KERN) {
		(void) policydb_optimize(&policydb);

		if (policydb_validate(NULL, &policydb) == -1)
			abort();
	}

	(void) check_assertions(NULL, &policydb, policydb.global->branch_list->avrules);

	devnull = fopen("/dev/null", "we");
	if (!devnull)
		goto exit;

	if (write_binary_policy(&policydb, devnull))
		abort();

	if (sepol_kernel_policydb_to_conf(devnull, &policydb))
		abort();

	if (sepol_kernel_policydb_to_cil(devnull, &policydb))
		abort();

exit:
	if (devnull != NULL)
		fclose(devnull);

	policydb_destroy(&policydb);
	sepol_sidtab_destroy(&sidtab);

	/* Non-zero return values are reserved for future use. */
	return 0;
}
