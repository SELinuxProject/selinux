/*
 * A security identifier table (sidtab) is a hash table
 * of security context structures indexed by SID value.
 */
#ifndef _SELINUX_AVC_SIDTAB_H_
#define _SELINUX_AVC_SIDTAB_H_

#include <selinux/selinux.h>
#include <selinux/avc.h>
#include "dso.h"

struct sidtab_node {
	struct security_id sid_s;
	struct sidtab_node *next;
};

#define SIDTAB_HASH_BITS 7
#define SIDTAB_HASH_BUCKETS (1 << SIDTAB_HASH_BITS)
#define SIDTAB_HASH_MASK (SIDTAB_HASH_BUCKETS-1)
#define SIDTAB_SIZE SIDTAB_HASH_BUCKETS

struct sidtab {
	struct sidtab_node **htable;
	unsigned nel;
};

int sidtab_init(struct sidtab *s) hidden;
int sidtab_insert(struct sidtab *s, const char * ctx) hidden;

int sidtab_context_to_sid(struct sidtab *s,
			  const char * ctx, security_id_t * sid) hidden;

void sidtab_sid_stats(struct sidtab *s, char *buf, int buflen) hidden;
void sidtab_destroy(struct sidtab *s) hidden;

#endif				/* _SELINUX_AVC_SIDTAB_H_ */
