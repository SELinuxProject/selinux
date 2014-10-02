/*
 * Copyright 2014 Tresys Technology, LLC. All rights reserved.
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
#include <string.h>
#include "cil_mem.h"
#include "cil_strpool.h"

#include "cil_log.h"
#define CIL_STRPOOL_TABLE_SIZE 1 << 15

struct cil_strpool_entry {
	char *str;
};

static hashtab_t cil_strpool_tab = NULL;

static unsigned int cil_strpool_hash(hashtab_t h, hashtab_key_t key)
{
	char *p, *keyp;
	size_t size;
	unsigned int val;

	val = 0;
	keyp = (char*)key;
	size = strlen(keyp);
	for (p = keyp; ((size_t) (p - keyp)) < size; p++)
		val =
		    (val << 4 | (val >> (8 * sizeof(unsigned int) - 4))) ^ (*p);
	return val & (h->size - 1);
}

static int cil_strpool_compare(hashtab_t h __attribute__ ((unused)), hashtab_key_t key1, hashtab_key_t key2)
{
	char *keyp1 = (char*)key1;
	char *keyp2 = (char*)key2;
	return strcmp(keyp1, keyp2);
}

char *cil_strpool_add(const char *str)
{
	struct cil_strpool_entry *strpool_ref = NULL;

	strpool_ref = hashtab_search(cil_strpool_tab, (hashtab_key_t)str);
	if (strpool_ref == NULL) {
		strpool_ref = cil_malloc(sizeof(*strpool_ref));
		strpool_ref->str = cil_strdup(str);
		int rc = hashtab_insert(cil_strpool_tab, (hashtab_key_t)strpool_ref->str, strpool_ref);
		if (rc != SEPOL_OK) {
			(*cil_mem_error_handler)();
		}
	}

	return strpool_ref->str;
}

static int cil_strpool_entry_destroy(hashtab_key_t k __attribute__ ((unused)), hashtab_datum_t d, void *args __attribute__ ((unused)))
{
	struct cil_strpool_entry *strpool_ref = (struct cil_strpool_entry*)d;
	free(strpool_ref->str);
	free(strpool_ref);
	return SEPOL_OK;
}

void cil_strpool_init(void)
{
	cil_strpool_tab = hashtab_create(cil_strpool_hash, cil_strpool_compare, CIL_STRPOOL_TABLE_SIZE);
	if (cil_strpool_tab == NULL) {
		(*cil_mem_error_handler)();
	}
}

void cil_strpool_destroy(void)
{
	hashtab_map(cil_strpool_tab, cil_strpool_entry_destroy, NULL);
	hashtab_destroy(cil_strpool_tab);
}
