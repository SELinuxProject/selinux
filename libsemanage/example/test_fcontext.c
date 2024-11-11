#include <semanage/fcontext_record.h>
#include <semanage/semanage.h>
#include <semanage/fcontexts_local.h>
#include <sepol/sepol.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

int main(const int argc, const char **argv) {
	semanage_handle_t *sh = NULL;
	semanage_fcontext_t *fcontext;
	semanage_context_t *con;
	semanage_fcontext_key_t *k;

	int exist = 0;
	sh = semanage_handle_create();
	if (sh == NULL) {
		perror("Can't create semanage handle\n");
		return -1;
	}
        if (semanage_access_check(sh) < 0) {
		perror("Semanage access check failed\n");
		return -1;
	}
        if (semanage_connect(sh) < 0) {
		perror("Semanage connect failed\n");
		return -1;
	}

	if (semanage_fcontext_key_create(sh, argv[2], SEMANAGE_FCONTEXT_REG, &k) < 0) {
		fprintf(stderr, "Could not create key for %s", argv[2]);
		return -1;
	}

	if(semanage_fcontext_exists(sh, k, &exist) < 0) {
		fprintf(stderr,"Could not check if key exists for %s", argv[2]);
		return -1;
	}
	if (exist) {
		fprintf(stderr,"Could create %s mapping already exists", argv[2]);
		return -1;
	}

	if (semanage_fcontext_create(sh, &fcontext) < 0) {
		fprintf(stderr,"Could not create file context for %s", argv[2]);
		return -1;
	}
	semanage_fcontext_set_expr(sh, fcontext, argv[2]);

	if (semanage_context_from_string(sh, argv[1], &con)) {
		fprintf(stderr,"Could not create context using %s for file context %s", argv[1], argv[2]);
		return -1;
	}

	if (semanage_fcontext_set_con(sh, fcontext, con) < 0) {
		fprintf(stderr,"Could not set file context for %s", argv[2]);
		return -1;
	}

	semanage_fcontext_set_type(fcontext, SEMANAGE_FCONTEXT_REG);

	if(semanage_fcontext_modify_local(sh, k, fcontext) < 0) {
		fprintf(stderr,"Could not add file context for %s", argv[2]);
		return -1;
	}
	semanage_fcontext_key_free(k);
	semanage_fcontext_free(fcontext);

	return 0;
}

