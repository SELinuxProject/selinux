/*
 * Implementation of the userspace SID hashtable.
 *
 * Author : Eamon Walsh, <ewalsh@epoch.ncsc.mil>
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "selinux_internal.h"
#include <selinux/avc.h>
#include "avc_sidtab.h"
#include "avc_internal.h"

static inline unsigned sidtab_hash(const char * key)
{
	char *p, *keyp;
	unsigned int size;
	unsigned int val;

	val = 0;
	keyp = (char *)key;
	size = strlen(keyp);
	for (p = keyp; (unsigned int)(p - keyp) < size; p++)
		val =
		    (val << 4 | (val >> (8 * sizeof(unsigned int) - 4))) ^ (*p);
	return val & (SIDTAB_SIZE - 1);
}

int sidtab_init(struct sidtab *s)
{
	int i, rc = 0;

	s->htable = (struct sidtab_node **)avc_malloc
	    (sizeof(struct sidtab_node *) * SIDTAB_SIZE);

	if (!s->htable) {
		rc = -1;
		goto out;
	}
	for (i = 0; i < SIDTAB_SIZE; i++)
		s->htable[i] = NULL;
	s->nel = 0;
      out:
	return rc;
}

int sidtab_insert(struct sidtab *s, const char * ctx)
{
	int hvalue, rc = 0;
	struct sidtab_node *newnode;
	char * newctx;

	newnode = (struct sidtab_node *)avc_malloc(sizeof(*newnode));
	if (!newnode) {
		rc = -1;
		goto out;
	}
	newctx = (char *) strdup(ctx);
	if (!newctx) {
		rc = -1;
		avc_free(newnode);
		goto out;
	}

	hvalue = sidtab_hash(newctx);
	newnode->next = s->htable[hvalue];
	newnode->sid_s.ctx = newctx;
	newnode->sid_s.refcnt = 1;	/* unused */
	s->htable[hvalue] = newnode;
	s->nel++;
      out:
	return rc;
}

int
sidtab_context_to_sid(struct sidtab *s,
		      const char * ctx, security_id_t * sid)
{
	int hvalue, rc = 0;
	struct sidtab_node *cur;

	*sid = NULL;
	hvalue = sidtab_hash(ctx);

      loop:
	cur = s->htable[hvalue];
	while (cur != NULL && strcmp(cur->sid_s.ctx, ctx))
		cur = cur->next;

	if (cur == NULL) {	/* need to make a new entry */
		rc = sidtab_insert(s, ctx);
		if (rc)
			goto out;
		goto loop;	/* find the newly inserted node */
	}

	*sid = &cur->sid_s;
      out:
	return rc;
}

void sidtab_sid_stats(struct sidtab *h, char *buf, int buflen)
{
	int i, chain_len, slots_used, max_chain_len;
	struct sidtab_node *cur;

	slots_used = 0;
	max_chain_len = 0;
	for (i = 0; i < SIDTAB_SIZE; i++) {
		cur = h->htable[i];
		if (cur) {
			slots_used++;
			chain_len = 0;
			while (cur) {
				chain_len++;
				cur = cur->next;
			}

			if (chain_len > max_chain_len)
				max_chain_len = chain_len;
		}
	}

	snprintf(buf, buflen,
		 "%s:  %u SID entries and %d/%d buckets used, longest "
		 "chain length %d\n", avc_prefix, h->nel, slots_used,
		 SIDTAB_SIZE, max_chain_len);
}

void sidtab_destroy(struct sidtab *s)
{
	int i;
	struct sidtab_node *cur, *temp;

	if (!s)
		return;

	for (i = 0; i < SIDTAB_SIZE; i++) {
		cur = s->htable[i];
		while (cur != NULL) {
			temp = cur;
			cur = cur->next;
			freecon(temp->sid_s.ctx);
			avc_free(temp);
		}
		s->htable[i] = NULL;
	}
	avc_free(s->htable);
	s->htable = NULL;
}
