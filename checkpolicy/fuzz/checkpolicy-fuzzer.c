#include <assert.h>
#include <unistd.h>
#include <sys/mman.h>

#include <sepol/debug.h>
#include <sepol/kernel_to_cil.h>
#include <sepol/kernel_to_conf.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/services.h>
#include <sepol/policydb/hierarchy.h>
#include <sepol/policydb/expand.h>
#include <sepol/policydb/link.h>

#include "queue.h"

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

extern int mlspol;
extern policydb_t *policydbp;
extern queue_t id_queue;
extern unsigned int policydb_errors;

extern int yynerrs;
extern FILE *yyin;
extern void init_parser(int);
extern int yyparse(void);
extern void yyrestart(FILE *);
extern void set_source_file(const char *name);

static ssize_t full_write(int fd, const void *buf, size_t count)
{
	ssize_t written = 0;

	while (count > 0) {
		ssize_t ret = write(fd, buf, count);
		if (ret < 0) {
			if (errno == EINTR)
				continue;

			return ret;
		}

		if (ret == 0)
			break;

		written += ret;
		buf = (const unsigned char *)buf + (size_t)ret;
		count -= (size_t)ret;
	}

	return written;
}

static int read_source_policy(policydb_t *p, const uint8_t *data, size_t size)
{
	int fd;
	ssize_t wr;

	fd = memfd_create("fuzz-input", MFD_CLOEXEC);
	if (fd < 0)
		return -1;

	wr = full_write(fd, data, size);
	if (wr < 0 || (size_t)wr != size) {
		close(fd);
		return -1;
	}

	fsync(fd);

	yynerrs = 0;

	yyin = fdopen(fd, "re");
	if (!yyin) {
		close(fd);
		return -1;
	}

	rewind(yyin);

	set_source_file("fuzz-input");

	id_queue = queue_create();
	if (id_queue == NULL) {
		fclose(yyin);
		return -1;
	}

	policydbp = p;
	mlspol = p->mls;

	init_parser(1);

	if (yyparse() || policydb_errors) {
		queue_destroy(id_queue);
		fclose(yyin);
		return -1;
	}

	rewind(yyin);
	init_parser(2);
	set_source_file("fuzz-input");
	yyrestart(yyin);

	if (yyparse() || policydb_errors) {
		queue_destroy(id_queue);
		fclose(yyin);
		return -1;
	}

	queue_destroy(id_queue);
	fclose(yyin);

	return 0;
}

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
	policydb_t parsepolicydb = {};
	policydb_t kernpolicydb = {};
	sidtab_t sidtab = {};
	FILE *devnull = NULL;

	sepol_debug(0);
	sepol_set_policydb(&parsepolicydb);
	sepol_set_sidtab(&sidtab);

	if (policydb_init(&parsepolicydb))
		goto exit;

	parsepolicydb.policy_type = POLICY_BASE;
	parsepolicydb.mls = 1;
	parsepolicydb.handle_unknown = DENY_UNKNOWN;
	policydb_set_target_platform(&parsepolicydb, SEPOL_TARGET_SELINUX);

	if (read_source_policy(&parsepolicydb, data, size))
		goto exit;

	if (hierarchy_check_constraints(NULL, &parsepolicydb))
		goto exit;

	if (link_modules(NULL, &parsepolicydb, NULL, 0, 0))
		goto exit;

	if (policydb_init(&kernpolicydb))
		goto exit;

	if (expand_module(NULL, &parsepolicydb, &kernpolicydb, 0, 1))
		goto exit;

	assert(kernpolicydb.policyvers     == POLICYDB_VERSION_MAX);
	assert(kernpolicydb.policy_type    == POLICY_KERN);
	assert(kernpolicydb.handle_unknown == SEPOL_DENY_UNKNOWN);
	assert(kernpolicydb.mls            == 1);

	if (policydb_load_isids(&kernpolicydb, &sidtab))
		goto exit;

	if (policydb_optimize(&kernpolicydb))
		goto exit;

	if (policydb_sort_ocontexts(&kernpolicydb))
		goto exit;

	devnull = fopen("/dev/null", "we");
	if (devnull == NULL)
		goto exit;

	(void) write_binary_policy(&kernpolicydb, devnull);

	(void) sepol_kernel_policydb_to_conf(devnull, &kernpolicydb);

	(void) sepol_kernel_policydb_to_cil(devnull, &kernpolicydb);

exit:
	if (devnull != NULL)
		fclose(devnull);

	sepol_sidtab_destroy(&sidtab);
	policydb_destroy(&kernpolicydb);
	policydb_destroy(&parsepolicydb);

	/* Non-zero return values are reserved for future use. */
	return 0;
}
