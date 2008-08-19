
/* Author : Stephen Smalley, <sds@epoch.ncsc.mil> */

/* FLASK */

/*
 * Implementation of the symbol table type.
 */

#include <string.h>
#include <sepol/policydb/hashtab.h>
#include <sepol/policydb/symtab.h>

static unsigned int symhash(hashtab_t h, hashtab_key_t key)
{
	char *p, *keyp;
	size_t size;
	unsigned int val;

	val = 0;
	keyp = (char *)key;
	size = strlen(keyp);
	for (p = keyp; ((size_t) (p - keyp)) < size; p++)
		val =
		    (val << 4 | (val >> (8 * sizeof(unsigned int) - 4))) ^ (*p);
	return val & (h->size - 1);
}

static int symcmp(hashtab_t h
		  __attribute__ ((unused)), hashtab_key_t key1,
		  hashtab_key_t key2)
{
	char *keyp1, *keyp2;

	keyp1 = (char *)key1;
	keyp2 = (char *)key2;
	return strcmp(keyp1, keyp2);
}

int symtab_init(symtab_t * s, unsigned int size)
{
	s->table = hashtab_create(symhash, symcmp, size);
	if (!s->table)
		return -1;
	s->nprim = 0;
	return 0;
}

/* FLASK */
