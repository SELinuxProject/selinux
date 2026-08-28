#include <sepol/debug.h>
#include <sepol/module.h>
#include <sepol/module_to_cil.h>

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

// set to 1 to enable more verbose libsepol logging
#ifndef VERBOSE
#define VERBOSE 0
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	sepol_module_package_t *mod = NULL;
	struct sepol_policy_file *spf = NULL;
	FILE *devnull = NULL;

	sepol_debug(VERBOSE);

	if (sepol_policy_file_create(&spf))
		goto exit;

	sepol_policy_file_set_mem(spf, (char *)data, size);

	if (sepol_module_package_create(&mod))
		goto exit;

	if (sepol_module_package_read(mod, spf, VERBOSE))
		goto exit;

	devnull = fopen("/dev/null", "we");
	if (!devnull)
		goto exit;

	/* sepol_module_package_read() stores contexts sections as raw blobs
	 * without validating their text syntax; sepol_module_package_to_cil()
	 * is the first place that parses them, so a graceful error return here
	 * is expected behaviour for malformed input, not a bug. */
	(void)sepol_module_package_to_cil(devnull, mod);

exit:
	if (devnull)
		fclose(devnull);
	sepol_module_package_free(mod);
	sepol_policy_file_free(spf);

	/* Non-zero return values are reserved for future use. */
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
