#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sepol/cil/cil.h>

int main(int argc, char **argv)
{
	assert(argc == 3);
	FILE *f = fopen(argv[1], "rb");
	assert(f);
	char text[8192];
	size_t n = fread(text, 1, sizeof(text), f);
	assert(n && n < sizeof(text) && !ferror(f));
	assert(!fclose(f));
	cil_db_t *db;
	sepol_policydb_t *p;
	cil_db_init(&db);
	assert(!cil_add_file(db, argv[1], text, n));
	assert(!cil_compile(db));
	assert(!cil_build_policydb(db, &p));
	void *image;
	size_t len;
	assert(!sepol_policydb_to_image(NULL, p, &image, &len));
	f = fopen(argv[2], "wb");
	assert(f && fwrite(image, 1, len, f) == len);
	assert(!fclose(f));
	free(image);
	sepol_policydb_free(p);
	cil_db_destroy(&db);
	return 0;
}
