
/* Copyright (c) 2008-2009 Nall Design Works
   Copyright 2006 Trusted Computer Solutions, Inc. */

/*
 Exported Interface

 int init_translations(void);
 void finish_context_translations(void);
 int trans_context(const security_context_t, security_context_t *);
 int untrans_context(const security_context_t, security_context_t *);

*/

#include <math.h>
#include <glob.h>
#include <values.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <ctype.h>
#include <selinux/selinux.h>
#include <selinux/context.h>
#include <syslog.h>
#include <errno.h>
#include <pcre.h>
#include <ctype.h>
#include <time.h>
#include <sys/time.h>


#include "mls_level.h"
#include "mcstrans.h"

#define N_BUCKETS 1453
#define OVECCOUNT (512*3)

#define log_error(fmt, ...) fprintf(stderr, fmt, __VA_ARGS__)

#ifdef DEBUG
#define log_debug(fmt, ...) fprintf(stderr, fmt, __VA_ARGS__)
#else
#define log_debug(fmt, ...) ;
#endif

static unsigned int maxbit=0;

/* Define data structures */
typedef struct context_map {
	char *raw;
	char *trans;
} context_map_t;

typedef struct context_map_node {
	char *key;
	context_map_t *map;
	struct context_map_node *next;
} context_map_node_t;

typedef struct affix {
	char *text;
	struct affix *next;
} affix_t;

typedef struct word {
	char *text;
	ebitmap_t cat;
	ebitmap_t normal;
	ebitmap_t inverse;
	struct word *next;
} word_t;

typedef struct word_group {
	char *name;
	char *whitespace;
	char *join;

	affix_t *prefixes;
	affix_t *suffixes;
	word_t *words;

	pcre *prefix_regexp;
	pcre *word_regexp;
	pcre *suffix_regexp;

	ebitmap_t def;

	word_t **sword;
	unsigned int sword_len;

	struct word_group *next;
} word_group_t;

typedef struct base_classification {
	char *trans;
	mls_level_t *level;
	struct base_classification *next;
} base_classification_t;

typedef struct domain {
	char *name;

	context_map_node_t *raw_to_trans[N_BUCKETS];
	context_map_node_t *trans_to_raw[N_BUCKETS];

	base_classification_t *base_classifications;
	word_group_t *groups;

	pcre *base_classification_regexp;
	struct domain *next;
} domain_t;

static domain_t *domains;

typedef struct sens_constraint {
	char op;
	char *text;
	unsigned int sens;
	ebitmap_t cat;
	struct sens_constraint *next;
} sens_constraint_t;

static sens_constraint_t *sens_constraints;

typedef struct cat_constraint {
	char op;
	char *text;
	int nbits;
	ebitmap_t mask;
	ebitmap_t cat;
	struct cat_constraint *next;
} cat_constraint_t;

static cat_constraint_t *cat_constraints;

unsigned int
hash(const char *str) {
	unsigned int hash = 5381;
	int c;

	while ((c = *(unsigned const char *)str++))
		hash = ((hash << 5) + hash) + c;

	return hash;
}

static int
add_to_hashtable(context_map_node_t **table, char *key, context_map_t *map) {
	unsigned int bucket = hash(key) % N_BUCKETS;
	context_map_node_t **n;
	for (n = &table[bucket]; *n; n = &(*n)->next)
		;
	*n = malloc(sizeof(context_map_node_t));
	if (! *n)
		goto err;
	(*n)->key = key;
	(*n)->map = map;
	(*n)->next = NULL;
	return 0;
err:
	syslog(LOG_ERR, "add_to_hashtable: allocation error");
	return -1;
}

static int
numdigits(unsigned int n)
{
	int count = 1;
	while ((n = n / 10))
		count++;
	return count;
}

static int
parse_category(ebitmap_t *e, const char *raw, int allowinverse)
{
	int inverse = 0;
	unsigned int low, high;
	while (*raw) {
		if (allowinverse && *raw == '~') {
			inverse = !inverse;
			raw++;
			continue;
		}
		if (sscanf(raw,"c%u", &low) != 1)
			return -1;
		raw += numdigits(low) + 1;
		if (*raw == '.') {
			raw++;
			if (sscanf(raw,"c%u", &high) != 1)
				return -1;
			raw += numdigits(high) + 1;
		} else {
			high = low;
		}
		while (low <= high) {
			if (low >= maxbit)
				maxbit = low + 1;
			if (ebitmap_set_bit(e, low, inverse ? 0 : 1) < 0)
				return -1;
			low++;
		}
		if (*raw == ',') {
			raw++;
			inverse = 0;
		} else if (*raw != '\0') {
			return -1;
		}
	}
	return 0;
}

int
parse_ebitmap(ebitmap_t *e, ebitmap_t *def, const char *raw) {
	int rc = ebitmap_cpy(e, def);
	if (rc < 0)
		return rc;
	rc = parse_category(e, raw, 1);
	if (rc < 0)
		return rc;
	return 0;
}

mls_level_t *
parse_raw(const char *raw) {
	mls_level_t *mls = calloc(1, sizeof(mls_level_t));
	if (!mls)
		goto err;
	if (sscanf(raw,"s%u", &mls->sens) != 1)
		goto err;
	raw += numdigits(mls->sens) + 1;
	if (*raw == ':') {
		raw++;
		if (parse_category(&mls->cat, raw, 0) < 0)
			goto err;
	} else if (*raw != '\0') {
		goto err;
	}

	return mls;

err:
	ebitmap_destroy(&mls->cat);
	free(mls);
	return NULL;
}

void
destroy_word(word_t **list, word_t *word) {
	if (!word) {
		return;
	}
	for (; list && *list; list = &(*list)->next) {
		if (*list == word) {
			*list = word->next;
			break;
		}
	}
	free(word->text);
	ebitmap_destroy(&word->cat);
	ebitmap_destroy(&word->normal);
	ebitmap_destroy(&word->inverse);
	memset(word, 0, sizeof(word_t));
	free(word);
}

word_t *
create_word(word_t **list, const char *text) {
	word_t *w = calloc(1, sizeof(word_t));
	if (!w) {
		goto err;
	}
	w->text = strdup(text);
	if (!w->text) {
		goto err;
	}
	if (list) {
		for (; *list; list = &(*list)->next)
			;
		*list = w;
	}

	return w;

err:
	log_error("create_word: allocation error %s", strerror(errno));
	destroy_word(NULL, w);
	return NULL;
}

void
destroy_group(word_group_t **list, word_group_t *group) {
	for (; list && *list; list = &(*list)->next) {
		if (*list == group) {
			*list = group->next;
			break;
		}
	}
	while(group->prefixes) {
		affix_t *next = group->prefixes->next;
		free(group->prefixes->text);
		free(group->prefixes);
		group->prefixes=next;
	}
	while(group->suffixes) {
		affix_t *next = group->suffixes->next;
		free(group->suffixes->text);
		free(group->suffixes);
		group->suffixes=next;
	}
	while(group->words)
		destroy_word(&group->words, group->words);
	free(group->whitespace);
	free(group->name);
	free(group->sword);
	free(group->join);
	pcre_free(group->prefix_regexp);
	pcre_free(group->word_regexp);
	pcre_free(group->suffix_regexp);
	ebitmap_destroy(&group->def);
	free(group);
}

word_group_t *
create_group(word_group_t **list, const char *name) {
	word_group_t *group = calloc(1, sizeof(word_group_t));
	if (!group)
		return NULL;
	group->name = strdup(name);
	if (!group->name) {
		goto err;
	}
	group->join = strdup(" ");
	if (!group->join) {
		goto err;
	}
	group->whitespace = strdup(" ");
	if (!group->whitespace) {
		goto err;
	}
	group->sword = NULL;

	if (list) {
		for (; *list; list = &(*list)->next)
			;
		*list = group;
	}

	return group;

err:
	log_error("allocation error %s", strerror(errno));
	destroy_group(NULL, group);
	return NULL;
}

void
destroy_domain(domain_t *domain) {
	int i;
        unsigned int rt = 0, tr = 0;
	for (i=0; i < N_BUCKETS; i++) {
		context_map_node_t *ptr;
		for (ptr = domain->trans_to_raw[i]; ptr;)  {
			context_map_node_t *t = ptr->next;
			free(ptr);
			ptr = t;
			tr++;
		}
		domain->trans_to_raw[i] = NULL;
	}
	for (i=0; i < N_BUCKETS; i++) {
		context_map_node_t *ptr;
		for (ptr = domain->raw_to_trans[i]; ptr;)  {
			context_map_node_t *t = ptr->next;
			free(ptr->map->raw);
			free(ptr->map->trans);
			free(ptr->map);
			free(ptr);
			ptr = t;
			rt++;
		}
		domain->raw_to_trans[i] = NULL;
	}
	while (domain->base_classifications)  {
		base_classification_t *next = domain->base_classifications->next;
		free(domain->base_classifications->trans);
		ebitmap_destroy(&domain->base_classifications->level->cat);
		free(domain->base_classifications->level);
		free(domain->base_classifications);
		domain->base_classifications = next;
	}
	pcre_free(domain->base_classification_regexp);
	while (domain->groups)
		destroy_group(&domain->groups, domain->groups);
	free(domain->name);
	free(domain);

	syslog(LOG_INFO, "cache sizes: tr = %u, rt = %u", tr, rt);
}

domain_t *
create_domain(const char *name) {
	domain_t *domain = calloc(1, sizeof(domain_t));
	if (!domain) {
		goto err;
	}
	domain->name = strdup(name);
	if (!domain->name) {
		goto err;
	}

	domain_t **d = &domains;
	for (; *d; d = &(*d)->next)
		;
	*d = domain;

	return domain;

err:
	log_error("allocation error %s", strerror(errno));
	destroy_domain(domain);
	return NULL;
}

int
add_word(word_group_t *group, char *raw, char *trans) {
	if (strchr(trans,'-')) {
		log_error("'%s'is invalid because '-' is illegal in modifiers.\n", trans);
		return -1;
	}
	word_t *word = create_word(&group->words, trans);
	int rc = parse_ebitmap(&word->cat, &group->def, raw);
	if (rc < 0) {
		log_error(" syntax error in %s\n", raw);
		destroy_word(&group->words, word);
		return -1;
	}
	if (ebitmap_andnot(&word->normal, &word->cat, &group->def, maxbit) < 0)
		return -1;

	ebitmap_t temp;
	if (ebitmap_xor(&temp, &word->cat, &group->def) < 0)
		return -1;
	if (ebitmap_and(&word->inverse, &temp, &group->def) < 0)
		return -1;
	ebitmap_destroy(&temp);

	return 0;
}

int
add_constraint(char op, char *raw, char *tok) {
	log_debug("%s\n", "add_constraint");
	ebitmap_t empty;
	ebitmap_init(&empty);
	if (!raw || !*raw) {
		syslog(LOG_ERR, "unable to parse line");
		return -1;
	}
	if (*raw == 's') {
		sens_constraint_t *constraint = calloc(1, sizeof(sens_constraint_t));
		if (!constraint) {
			log_error("allocation error %s", strerror(errno));
			return -1;
		}
		if (sscanf(raw,"s%u", &constraint->sens) != 1) {
			syslog(LOG_ERR, "unable to parse level");
			free(constraint);
			return -1;
		}
		if (parse_ebitmap(&constraint->cat, &empty, tok) < 0) {
			syslog(LOG_ERR, "unable to parse cat");
			free(constraint);
			return -1;
		}
		if (asprintf(&constraint->text, "%s%c%s", raw, op, tok) < 0) {
			log_error("asprintf failed %s", strerror(errno));
			return -1;
		}
		constraint->op = op;
		sens_constraint_t **p;
		for (p= &sens_constraints; *p; p = &(*p)->next)
                        ;
                *p = constraint;
		return 0;
	} else if (*raw == 'c' ) {
		cat_constraint_t *constraint = calloc(1, sizeof(cat_constraint_t));
		if (!constraint) {
			log_error("allocation error %s", strerror(errno));
			return -1;
		}
		if (parse_ebitmap(&constraint->mask, &empty, raw) < 0) {
			syslog(LOG_ERR, "unable to parse mask");
			free(constraint);
			return -1;
		}
		if (parse_ebitmap(&constraint->cat, &empty, tok) < 0) {
			syslog(LOG_ERR, "unable to parse cat");
			ebitmap_destroy(&constraint->mask);
			free(constraint);
			return -1;
		}
		if (asprintf(&constraint->text, "%s%c%s", raw, op, tok) < 0) {
			log_error("asprintf failed %s", strerror(errno));
			return -1;
		}
		constraint->nbits = ebitmap_cardinality(&constraint->cat);
		constraint->op = op;
		cat_constraint_t **p;
		for (p= &cat_constraints; *p; p = &(*p)->next)
                        ;
                *p = constraint;
		return 0;
	} else {
		return -1;
	}
	
	return 0;
}

int
violates_constraints(mls_level_t *l) {
	int nbits;
	sens_constraint_t *s;
	ebitmap_t common;
	for (s=sens_constraints; s; s=s->next) {
		if (s->sens == l->sens) {
			if (ebitmap_and(&common, &s->cat, &l->cat) < 0)
				return 1;
			nbits = ebitmap_cardinality(&common);
			ebitmap_destroy(&common);
			if (nbits) {
				char *text = mls_level_to_string(l);
				syslog(LOG_WARNING, "%s violates %s", text, s->text);
				free(text);
				return 1;
			}
		}
	}
	cat_constraint_t *c;
	for (c=cat_constraints; c; c=c->next) {
		if (ebitmap_and(&common, &c->mask, &l->cat) < 0)
			return 1;
		nbits = ebitmap_cardinality(&common);
		ebitmap_destroy(&common);
		if (nbits > 0) {
			if (ebitmap_and(&common, &c->cat, &l->cat) < 0)
				return 1;
			nbits = ebitmap_cardinality(&common);
			ebitmap_destroy(&common);
			if ((c->op == '!' && nbits) ||
			    (c->op == '>' && nbits != c->nbits)) {
				char *text = mls_level_to_string(l);
				syslog(LOG_WARNING, "%s violates %s (%d,%d)", text, c->text, nbits, c->nbits);
				free(text);
				return 1;
			}
		}
	}
	return 0;
}

void
destroy_sens_constraint(sens_constraint_t **list, sens_constraint_t *constraint) {
	if (!constraint) {
		return;
	}
	for (; list && *list; list = &(*list)->next) {
		if (*list == constraint) {
			*list = constraint->next;
			break;
		}
	}
	ebitmap_destroy(&constraint->cat);
	free(constraint->text);
	memset(constraint, 0, sizeof(sens_constraint_t));
	free(constraint);
}

void
destroy_cat_constraint(cat_constraint_t **list, cat_constraint_t *constraint) {
	if (!constraint) {
		return;
	}
	for (; list && *list; list = &(*list)->next) {
		if (*list == constraint) {
			*list = constraint->next;
			break;
		}
	}
	ebitmap_destroy(&constraint->mask);
	ebitmap_destroy(&constraint->cat);
	free(constraint->text);
	memset(constraint, 0, sizeof(cat_constraint_t));
	free(constraint);
}


static int
add_base_classification(domain_t *domain, char *raw, char *trans) {
	mls_level_t *level = parse_raw(raw);
	if (level) {
		base_classification_t **i;
		base_classification_t *base_classification = calloc(1, sizeof(base_classification_t));
		if (!base_classification) {
			log_error("allocation error %s", strerror(errno));
			return -1;
		}
		base_classification->trans=strdup(trans);
		if (!base_classification->trans) {
			log_error("allocation error %s", strerror(errno));
			free(base_classification);
			return -1;
		}
		base_classification->level=level;

		for (i=&domain->base_classifications; *i; i=&(*i)->next)
		;
		*i = base_classification;
			return 0;
		}
	log_error(" add_base_classification error %s %s\n", raw, trans);
	return -1;
}

static int
add_cache(domain_t *domain, char *raw, char *trans) {
	context_map_t *map = calloc(1, sizeof(context_map_t));
	if (!map) goto err;

	map->raw = strdup(raw);
	if (!map->raw) {
		goto err;
	}
	map->trans = strdup(trans);
	if (!map->trans) {
		goto err;
	}

	log_debug(" add_cache (%s,%s)\n", raw, trans);
	if (add_to_hashtable(domain->raw_to_trans, map->raw, map) < 0)
		goto err;

	if (add_to_hashtable(domain->trans_to_raw, map->trans, map) < 0)
		goto err;

	return 0;
err:
	log_error("%s: allocation error", "add_cache");
	return -1;
}

static context_map_t *
find_in_table(context_map_node_t **table, const char *key) {
	unsigned int bucket = hash(key) % N_BUCKETS;
	context_map_node_t **n;
	for (n = &table[bucket]; *n; n = &(*n)->next)
		if (!strcmp((*n)->key, key))
			return (*n)->map;
	return NULL;
}

char *
trim(char *str, const char *whitespace) {
	char *p = str + strlen(str);

	while (p > str && strchr(whitespace, *(p-1)) != NULL)
		*--p = 0;
	return str;
}

char *
triml(char *str, const char *whitespace) {
	char *p = str;

	while (*p && (strchr(whitespace, *p) != NULL))
		p++;
	return p;
}

int
update(char **p, char *const val) {
	free (*p);
	*p = strdup(val);
	if (!*p) {
		log_error("allocation error %s", strerror(errno));
		return -1;
	}
	return 0;
}

int
append(affix_t **affixes, const char *val) {
	affix_t *affix = calloc(1, sizeof(affix_t));
	if (!affix) {
		goto err;
	}
	affix->text = strdup(val);
	if (!affix->text)
		goto err;
	for (;*affixes; affixes = &(*affixes)->next)
		;
	*affixes = affix;
	return 0;

err:
	log_error("allocation error %s", strerror(errno));
	return -1;
}

static int read_translations(const char *filename);

/* Process line from translation file.
   Remove white space and set raw do data before the "=" and tok to data after it
   Modifies the data pointed to by the buffer parameter
 */
static int
process_trans(char *buffer) {
	static domain_t *domain;
	static word_group_t *group;
	static int base_classification;
	static int lineno = 0;
	char op='\0';

	lineno++;
	log_debug("%d: %s", lineno, buffer);

	/* zap leading whitespace */
	buffer = triml(buffer, "\t ");

	/* Ignore comments */
	if (*buffer == '#') return 0;
	char *comment = strpbrk (buffer, "#");
	if (comment) {
		*comment = '\0';
	}

	/* zap trailing whitespace */
	buffer = trim(buffer, "\t \r\n");

	if (*buffer == 0) return 0;

	char *delim = strpbrk (buffer, "=!>");
	if (! delim) {
		syslog(LOG_ERR, "invalid line (no !, = or >) %d", lineno);
		return -1;
	}

	op = *delim;
	*delim = '\0';
	char *raw = buffer;
	char *tok = delim+1;

	/* remove trailing/leading whitespace from the split tokens */
	trim(raw, "\t ");
	tok = triml(tok, "\t ");

	if (! *raw) {
		syslog(LOG_ERR, "invalid line %d", lineno);
		return -1;
	}

	if (! *tok) {
		syslog(LOG_ERR, "invalid line %d", lineno);
		return -1;
	}

	/* constraints have different syntax */
	if (op == '!' || op == '>') {
		return add_constraint(op, raw, tok);
	}

	if (!strcmp(raw, "Domain")) {
		domain = create_domain(tok);
		group = NULL;
		return 0;
	}

	if (!domain) {
		domain = create_domain("Default");
		if (!domain)
			return -1;
		group = NULL;
	}

	if (!group &&
	    (!strcmp(raw, "Whitespace") || !strcmp(raw, "Join") ||
	     !strcmp(raw, "Prefix") || !strcmp(raw, "Suffix") ||
		 !strcmp(raw, "Default"))) {
		syslog(LOG_ERR, "expected  ModifierGroup declaration on line %d", lineno);
		return -1;
	}

	if (!strcmp(raw, "Include")) {
		unsigned int n;
		glob_t g;
		g.gl_offs = 0;
		if (glob(tok, GLOB_ERR, NULL, &g) < 0) {
			globfree(&g);
			return -1;
		}
		for (n=0; n < g.gl_pathc; n++) {
			if (read_translations(g.gl_pathv[n]) < 0) {
				globfree(&g);
				return -1;
			}
		}
		globfree(&g);
	} else if (!strcmp(raw, "Base")) {
		base_classification = 1;
	} else if (!strcmp(raw, "ModifierGroup")) {
		group = create_group(&domain->groups, tok);
		if (!group)
			return -1;
		base_classification = 0;
	} else if (!strcmp(raw, "Whitespace")) {
		if (update (&group->whitespace, tok) < 0)
			return -1;
	} else if (!strcmp(raw, "Join")) {
		if (update (&group->join, tok) < 0)
			return -1;
	} else if (!strcmp(raw, "Prefix")) {
		if (append (&group->prefixes, tok) < 0)
			return -1;
	} else if (!strcmp(raw, "Suffix")) {
		if (append (&group->suffixes, tok) < 0)
			return -1;
	} else if (!strcmp(raw, "Default")) {
		ebitmap_t empty;
		ebitmap_init(&empty);
		if (parse_ebitmap(&group->def, &empty, tok) < 0) {
			syslog(LOG_ERR, "unable to parse Default %d", lineno);
			return -1;
		}
	} else if (group) {
		if (add_word(group, raw, tok) < 0) {
			syslog(LOG_ERR, "unable to add base_classification on line %d", lineno);
			return -1;
		}
	} else {
		if (base_classification) {
			if (add_base_classification(domain, raw, tok) < 0) {
				syslog(LOG_ERR, "unable to add base_classification on line %d", lineno);
				return -1;
			}
		}
		if (add_cache(domain, raw, tok) < 0)
			return -1;
	}
	return 0;
}

int
read_translations(const char *filename) {
	size_t size = 0;
	char *buffer = NULL;
	int rval = 0;

	FILE *cfg = fopen(filename,"r");
	if (!cfg) {
		syslog(LOG_ERR, "%s file open failed", filename);
		return -1;
	}

	__fsetlocking(cfg, FSETLOCKING_BYCALLER);
	while (getline(&buffer, &size, cfg) > 0) {
		if( process_trans(buffer) < 0 ) {
			syslog(LOG_ERR, "%s file read failed", filename);
			rval = -1;
			break;
		}
	}
	free(buffer);
	fclose(cfg);
	return rval;
}

int
init_translations(void) {
	if (is_selinux_mls_enabled() <= 0)
		return -1;

	return(read_translations(selinux_translations_path()));
}

char *
extract_range(const security_context_t incon) {
	context_t con = context_new(incon);
	if (!con) {
		syslog(LOG_ERR, "extract_range context_new(%s) failed: %s", incon, strerror(errno));
		return NULL;
	}

	const char *range = context_range_get(con);
	if (!range) {
		syslog(LOG_ERR, "extract_range: context_range_get(%s) failed: %m", incon);
		context_free(con);
		return NULL;
	}
	char *r = strdup(range);
	if (!r) {
		log_error("extract_range: allocation error %s", strerror(errno));
		return NULL;
	}
	context_free(con);
	return r;
}

char *
new_context_str(const security_context_t incon, const char *range) {
	char *rcon = NULL;
	context_t con = context_new(incon);
	if (!con) {
		goto exit;
	}
	context_range_set(con, range);
	rcon = strdup(context_str(con));
	if (!rcon) {
		goto exit;
	}

	return rcon;

exit:
	log_error("new_context_str: %s %s", incon, strerror(errno));
	return NULL;
}

char *
find_in_hashtable(const char *range, domain_t *domain, context_map_node_t **table) {
	char *trans = NULL;
	context_map_t *map = find_in_table(table, range);
	if (map) {
		trans = strdup((table == domain->raw_to_trans) ? map->trans: map->raw);
		if (!trans) {
			log_error("find_in_hashtable: allocation error %s", strerror(errno));
			return NULL;
		}
		log_debug(" found %s in hashtable returning %s\n", range, trans);
	}
	return trans;
}

void
emit_whitespace(char*buffer, char *whitespace) {
	strcat(buffer, "[");
	strcat(buffer, whitespace);
	strcat(buffer, "]");
}

static int
string_size(const void *p1, const void *p2) {
	return strlen(*(char **)p2) - strlen(*(char **)p1);
}

static int
word_size(const void *p1, const void *p2) {
	word_t *w1 = *(word_t **)p1;
	word_t *w2 = *(word_t **)p2;
	int w1_len=strlen(w1->text);
	int w2_len=strlen(w2->text);
	if (w1_len == w2_len)
		return strcmp(w1->text, w2->text);
	return (w2_len - w1_len);
}

void
build_regexp(pcre **r, char *buffer) {
	const char *error;
	int error_offset;
	if (*r)
		pcre_free(*r);
	*r = pcre_compile(buffer, PCRE_CASELESS, &error, &error_offset, NULL);
	if (error) {
		log_error("pcre=%s, error=%s\n", buffer, error ? error: "none");
	}
	buffer[0] = '\0';
}

int
build_regexps(domain_t *domain) {
	char buffer[1024 * 128];
	buffer[0] = '\0';
	base_classification_t *bc;
	word_group_t *g;
	affix_t *a;
	word_t *w;
	size_t n_el, i;

	for (n_el = 0, bc = domain->base_classifications; bc; bc = bc->next) {
		n_el++;
	}

	char **sortable = calloc(n_el, sizeof(char *));
	if (!sortable) {
		log_error("allocation error %s", strerror(errno));
		return -1;
	}

	for (i=0, bc = domain->base_classifications; bc; bc = bc->next) {
		sortable[i++] = bc->trans;
	}

	qsort(sortable, n_el, sizeof(char *), string_size);

	for (i = 0; i < n_el; i++) {
		strcat(buffer, sortable[i]);
		if (i < n_el) strcat(buffer,"|");
	}

	free(sortable);

	log_debug(">>> %s classification regexp=%s\n", domain->name, buffer);
	build_regexp(&domain->base_classification_regexp, buffer);

	for (g = domain->groups; g; g = g->next) {
		if (g->prefixes) {
			strcat(buffer,"(?:");
			for (a = g->prefixes; a; a = a->next) {
				strcat(buffer, a->text);
				if (a->next) strcat(buffer,"|");
			}
			strcat(buffer,")");
			strcat(buffer,"[ 	]+");
			log_debug(">>> %s %s prefix regexp=%s\n", domain->name, g->name, buffer);
			build_regexp(&g->prefix_regexp, buffer);
		}

		if (g->prefixes)
			strcat(buffer, "^");
		strcat(buffer, "(?:");

		g->sword_len=0;
		for (w = g->words; w; w = w->next)
			g->sword_len++;

		g->sword = calloc(g->sword_len, sizeof(word_t *));
		if (!g->sword) {
			log_error("allocation error %s", strerror(errno));
			return -1;
		}

		i=0;
		for (w = g->words; w; w = w->next)
			g->sword[i++]=w;

		qsort(g->sword, g->sword_len, sizeof(word_t *), word_size);

		for (i=0; i < g->sword_len; i++) {
			if (i) strcat(buffer,"|");
			strcat(buffer,"\\b");
			strcat(buffer, g->sword[i]->text);
			strcat(buffer,"\\b");
		}

		if (g->whitespace) {
			strcat(buffer,"|[");
			strcat(buffer, g->whitespace);
			strcat(buffer, "]+");
		}

		strcat(buffer, ")+");
		if (g->suffixes)
			strcat(buffer, "$");

		log_debug(">>> %s %s modifier regexp=%s\n", domain->name, g->name, buffer);
		build_regexp(&g->word_regexp, buffer);
		if (g->suffixes) {
			strcat(buffer,"[ 	]+");
			strcat(buffer,"(?:");
			for (a = g->suffixes; a; a = a->next) {
				strcat(buffer, a->text);
				if (a->next) strcat(buffer,"|");
			}
			strcat(buffer,")");
			log_debug(">>> %s %s suffix regexp=%s\n", domain->name, g->name, buffer);
			build_regexp(&g->suffix_regexp, buffer);
		}
	}

	return 0;
}

char *
compute_raw_from_trans(const char *level, domain_t *domain) {

#ifdef DEBUG
	struct timeval startTime;
	gettimeofday(&startTime, 0);
#endif

	int rc = 0;
	int ovector[OVECCOUNT];
	word_group_t *g = NULL;
	char *work = NULL;
	char *r = NULL;
	const char * match = NULL;
	int work_len;
	mls_level_t *mraw = NULL;
	ebitmap_t set, clear, tmp;

	ebitmap_init(&set);
	ebitmap_init(&clear);
	ebitmap_init(&tmp);

	work = strdup(level);
	if (!work) {
		log_error("compute_raw_from_trans: allocation error %s", strerror(errno));
		goto err;
	}
	work_len = strlen(work);

	if (!domain->base_classification_regexp)
		if (build_regexps(domain) < 0)
			goto err;
	if (!domain->base_classification_regexp)
		goto err;
	log_debug(" compute_raw_from_trans work = %s\n", work);
	rc = pcre_exec(domain->base_classification_regexp, 0, work, work_len, 0, PCRE_ANCHORED, ovector, OVECCOUNT);
	if (rc > 0) {
		match = NULL;
		pcre_get_substring(work, ovector, rc, 0, &match);
		log_debug(" compute_raw_from_trans match = %s len = %u\n", match, strlen(match));
		base_classification_t *bc;
		for (bc = domain->base_classifications; bc; bc = bc->next) {
			if (!strcmp(bc->trans, match)) {
				log_debug(" compute_raw_from_trans base classification %s matched %s\n", level, bc->trans);
				mraw = malloc(sizeof(mls_level_t));
				if (!mraw) {
					log_error("allocation error %s", strerror(errno));
					goto err;
				}
				if (mls_level_cpy(mraw, bc->level) < 0)
					goto err;
				break;
			}
		}

		memset(work + ovector[0], '#', ovector[1] - ovector[0]);
		char *p=work + ovector[0] + ovector[1];
		while (*p && (strchr(" 	", *p) != NULL))
			*p++ = '#';
		pcre_free((char *)match);
		match = NULL;
	} else {
		log_debug(" compute_raw_from_trans no base classification matched %s\n", level);
	}

	if (mraw == NULL) {
		goto err;
	}

	int complete = 0;
	int change = 1;
	while(change && !complete) {
		change = 0;
		for (g = domain->groups; g && !change && !complete; g = g->next) {
			int prefix = 0, suffix = 0;
			int prefix_offset = 0, prefix_len = 0;
			int suffix_offset = 0, suffix_len = 0;
			if (g->prefix_regexp) {
				rc = pcre_exec(g->prefix_regexp, 0, work, work_len, 0, 0, ovector, OVECCOUNT);
				if (rc > 0) {
					prefix = 1;
					prefix_offset = ovector[0];
					prefix_len = ovector[1] - ovector[0];
				}
			}
			if (g->suffix_regexp) {
				rc = pcre_exec(g->suffix_regexp, 0, work, work_len, 0, 0, ovector, OVECCOUNT);
				if (rc > 0) {
					suffix = 1;
					suffix_offset = ovector[0];
					suffix_len = ovector[1] - ovector[0];
				}
			}

/* anchors prefix ^, suffix $ */
			if (((!g->prefixes && !g->suffixes) ||
			     (g->prefixes && prefix) ||
			     (g->suffixes && suffix)) &&
			     g->word_regexp) {
				char *s = work + prefix_offset + prefix_len;
				int l = (suffix_len ? suffix_offset : work_len) - prefix_len - prefix_offset;
				rc = pcre_exec(g->word_regexp, 0, s, l, 0, 0, ovector, OVECCOUNT);
				if (rc > 0) {
					match = NULL;
					pcre_get_substring(s, ovector, rc, 0, &match);
					trim((char *)match, g->whitespace);
					if (*match) {
						char *p = triml((char *)match, g->whitespace);
						while (p && *p) {
							int plen = strlen(p);
							unsigned int i;
							for (i = 0; i < g->sword_len; i++) {
								word_t *w = g->sword[i];
								int wlen = strlen(w->text);
								if (plen >= wlen && !strncmp(w->text, p, strlen(w->text))){
									if (ebitmap_andnot(&set, &w->cat, &g->def, maxbit) < 0) goto err;

									if (ebitmap_xor(&tmp, &w->cat, &g->def) < 0) goto err;
									if (ebitmap_and(&clear, &tmp, &g->def) < 0) goto err;
									if (ebitmap_union(&mraw->cat, &set) < 0) goto err;

									ebitmap_destroy(&tmp);
									if (ebitmap_cpy(&tmp, &mraw->cat) < 0) goto err;
									ebitmap_destroy(&mraw->cat);
									if (ebitmap_andnot(&mraw->cat, &tmp, &clear, maxbit) < 0) goto err;

									ebitmap_destroy(&tmp);
									ebitmap_destroy(&set);
									ebitmap_destroy(&clear);
									p += strlen(w->text);
									change++;
									break;
								}
							}
							if (i == g->sword_len) {
								syslog(LOG_ERR, "conversion error");
								break;
							}
							p = triml(p, g->whitespace);
						}
						memset(work + prefix_offset, '#', prefix_len);
						memset(work + suffix_offset, '#', suffix_len);
						memset(s + ovector[0], '#', ovector[1] - ovector[0]);
					}
					pcre_free((void *)match);
					match = NULL;
				}
			}
/* YYY */
			complete=1;
			char *p = work;
			while(*p) {
				if (isalnum(*p++)) {
					complete=0;
					break;
				}
			}
		}
	}
	free(work);
	if (violates_constraints(mraw)) {
		complete = 0;
	}
	if (complete)
		r = mls_level_to_string(mraw);
	mls_level_destroy(mraw);
	free(mraw);

#ifdef DEBUG
	struct timeval stopTime;
	gettimeofday(&stopTime, 0);
	long int ms;
	if (startTime.tv_usec > stopTime.tv_usec)
		ms = (stopTime.tv_sec - startTime.tv_sec - 1) * 1000 + (stopTime.tv_usec/1000 + 1000 - startTime.tv_usec/1000);
	else
		ms = (stopTime.tv_sec - startTime.tv_sec    ) * 1000 + (stopTime.tv_usec/1000        - startTime.tv_usec/1000);
	log_debug(" compute_raw_from_trans in %ld ms'\n", ms);
#endif

	return r;

err:
	mls_level_destroy(mraw);
	free(mraw);
	free(work);
	pcre_free((void *)match);
	ebitmap_destroy(&tmp);
	ebitmap_destroy(&set);
	ebitmap_destroy(&clear);
	return NULL;
}

char *
compute_trans_from_raw(const char *level, domain_t *domain) {

#ifdef DEBUG
	struct timeval startTime;
	gettimeofday(&startTime, 0);
#endif

	word_group_t *g;
	mls_level_t *l = NULL;
	char *rval = NULL;
	word_group_t *groups = NULL;
	ebitmap_t bit_diff, temp, handled, nothandled, unhandled, orig_unhandled;

	ebitmap_init(&bit_diff);
	ebitmap_init(&temp);
	ebitmap_init(&handled);
	ebitmap_init(&nothandled);
	ebitmap_init(&unhandled);
	ebitmap_init(&orig_unhandled);

	if (!level)
		goto err;
	
	l = parse_raw(level);
	if (!l)
		goto err;
	log_debug(" compute_trans_from_raw raw = %s\n", level);

/* YYY */
	/* check constraints */
	if (violates_constraints(l)) {
		syslog(LOG_ERR, "%s violates constraints", level);
		goto err;
	}

	int doInverse = l->sens > 0;

	base_classification_t *bc, *last = NULL;
	int done = 0;
	for (bc = domain->base_classifications; bc && !done; bc = bc->next) {
		if (l->sens == bc->level->sens) {
			/* skip if alias of last bc */
			if (last &&
			    last->level->sens == bc->level->sens &&
			    ebitmap_cmp(&last->level->cat, &bc->level->cat) == 0)
				continue;

			/* compute bits not consumed by base classification */
			if (ebitmap_xor(&unhandled, &l->cat, &bc->level->cat) < 0)
				goto err;
			if (ebitmap_cpy(&orig_unhandled, &unhandled) < 0)
				goto err;

			/* prebuild groups */
			for (g = domain->groups; g; g = g->next) {
				word_group_t **t;
				for (t = &groups; *t; t = &(*t)->next)
					if (!strcmp(g->name, (*t)->name))
						break;

				if (! *t) {
					word_group_t *wg = create_group(&groups, g->name);
					if (g->prefixes)
						if (append(&wg->prefixes, g->prefixes->text) < 0)
							goto err;
					if (g->suffixes)
						if (append(&wg->suffixes, g->suffixes->text) < 0)
							goto err;
					if (g->join)
						if (update(&wg->join, g->join) < 0)
							goto err;
				}
			}

			int loops, hamming, change=1;
			for (loops = 50; ebitmap_cardinality(&unhandled) && loops > 0 && change; loops--) {
				change = 0;
				hamming = 10000;
				if (ebitmap_xor(&handled, &unhandled, &orig_unhandled) < 0)
					goto err;
				if (ebitmap_not(&nothandled, &handled, maxbit) < 0)
					goto err;
				word_group_t *currentGroup = NULL;
				word_t *currentWord = NULL;
				for (g = domain->groups; g && hamming; g = g->next) {
					word_t *w;
					for (w = g->words; w && hamming; w = w->next) {
						int cardinality = ebitmap_cardinality(&w->normal);
						/* If the word is all inverse bits and the level does not have inverse bits - skip */
						if (cardinality && !doInverse) {
							continue;
						}

						/* if only unhandled bits are different */
						if (ebitmap_or(&temp, &w->normal, &w->inverse) < 0)
							goto err;
						if (ebitmap_and(&bit_diff, &temp, &nothandled) < 0)
							goto err;
						ebitmap_destroy(&temp);
// xor bit_diff handled?
						if (ebitmap_and(&temp, &bit_diff, &unhandled) < 0)
							goto err;
						if (ebitmap_cmp(&bit_diff, &temp)) {
							int h = ebitmap_hamming_distance(&bit_diff, &unhandled);
							if (h < hamming) {
								hamming = h;
								currentGroup = g;
								currentWord = w;
							}
						}
						ebitmap_destroy(&bit_diff);
						ebitmap_destroy(&temp);
					}
				}
				ebitmap_destroy(&handled);
				ebitmap_destroy(&nothandled);

				if (currentWord) {
					if (ebitmap_xor(&bit_diff, &currentWord->cat, &bc->level->cat) < 0)
						goto err;

					if (ebitmap_cpy(&temp, &unhandled) < 0)
						goto err;
					ebitmap_destroy(&unhandled);
					if (ebitmap_andnot(&unhandled, &temp, &bit_diff, maxbit) < 0)
						goto err;

					ebitmap_destroy(&bit_diff);
					ebitmap_destroy(&temp);

					word_group_t **t;
					for (t = &groups; *t; t = &(*t)->next)
						if (!strcmp(currentGroup->name, (*t)->name))
							break;
					create_word(&(*t)->words, currentWord->text);
					change++;
				}
			}

			done = (ebitmap_cardinality(&unhandled) == 0);
			ebitmap_destroy(&unhandled);
			ebitmap_destroy(&orig_unhandled);
			if (done) {
				char buffer[9999];
				buffer[0] = 0;
				strcat(buffer, bc->trans);
				strcat(buffer, " ");
				for (g=groups; g; g = g->next) {
					if (g->words && g->prefixes) {
						strcat(buffer, g->prefixes->text);
						strcat(buffer, " ");
					}
					word_t *w;
					for (w=g->words; w; w = w->next) {
						strcat(buffer, w->text);
						if (w->next)
							strcat(buffer, g->join);
					}
					if (g->words && g->suffixes) {
						strcat(buffer, " ");
						strcat(buffer, g->suffixes->text);
					}
					word_group_t *n = g->next;
					while(g->words && n) {
						if (n->words) {
							strcat(buffer, " ");
							break;
						}
						n = n->next;
					}
				}
				rval = strdup(buffer);
				if (!rval) {
					log_error("compute_trans_from_raw: allocation error %s", strerror(errno));
					goto err;
				}
			}
			/* clean up */
			while (groups)
				destroy_group(&groups, groups);
		}
		last = bc;
	}
	if (l) {
		mls_level_destroy(l);
		free(l);
	}

#ifdef DEBUG
	struct timeval stopTime;
	gettimeofday(&stopTime, 0);
	long int ms;
	if (startTime.tv_usec > stopTime.tv_usec)
		ms = (stopTime.tv_sec - startTime.tv_sec - 1) * 1000 + (stopTime.tv_usec/1000 + 1000 - startTime.tv_usec/1000);
	else
		ms = (stopTime.tv_sec - startTime.tv_sec    ) * 1000 + (stopTime.tv_usec/1000        - startTime.tv_usec/1000);

	log_debug(" compute_trans_from_raw in %ld ms'\n", ms);
#endif

	return rval;

err:
	while (groups)
		destroy_group(&groups, groups);
	mls_level_destroy(l);
	free(l);
	return NULL;
}

int
trans_context(const security_context_t incon, security_context_t *rcon) {
	char *trans = NULL;
	*rcon = NULL;

#ifdef DEBUG
	struct timeval startTime;
	gettimeofday(&startTime, 0);
#endif

	log_debug(" trans_context input = %s\n", incon);
	char *range = extract_range(incon);
	if (!range) return -1;

	domain_t *domain = domains;
	for (;domain; domain = domain->next) {
		trans = find_in_hashtable(range, domain, domain->raw_to_trans);
		if (trans) break;

		/* try split and translate */
		char *lrange = NULL, *urange = NULL;
		char *ltrans = NULL, *utrans = NULL;
		char *dashp = strchr(range,'-');
		if (dashp) {
			*dashp = 0;
			lrange = range;
			urange = dashp+1;
		} else {
			trans = compute_trans_from_raw(range, domain);
			if (trans)
				if (add_cache(domain, range, trans) < 0)
					return -1;
		}

		if (lrange && urange) {
			ltrans = find_in_hashtable(lrange, domain, domain->raw_to_trans);
			if (! ltrans) {
				ltrans = compute_trans_from_raw(lrange, domain);
				if (ltrans) {
					if (add_cache(domain, lrange, ltrans) < 0)
						return -1;
				} else {
					ltrans = strdup(lrange);
					if (! ltrans) {
						log_error("strdup failed %s", strerror(errno));
						return -1;
					}
				}
			}

			utrans = find_in_hashtable(urange, domain, domain->raw_to_trans);
			if (! utrans) {
				utrans = compute_trans_from_raw(urange, domain);
				if (utrans) {
					if (add_cache(domain, urange, utrans) < 0)
						return -1;
				} else {
					utrans = strdup(urange);
					if (! utrans) {
						log_error("strdup failed %s", strerror(errno));
 						return -1;
 					}
 				}
			}

			if (strcmp(ltrans, utrans) == 0) {
				if (asprintf(&trans, "%s", ltrans) < 0) {
					log_error("asprintf failed %s", strerror(errno));
					return -1;
				}
			} else {
				if (asprintf(&trans, "%s-%s", ltrans, utrans) < 0) {
					log_error("asprintf failed %s", strerror(errno));
					return -1;
				}
			}
			free(ltrans);
			free(utrans);
			*dashp = '-';
			break;
		}
		if (dashp)
			*dashp = '-';
	}

	if (trans) {
		*rcon = new_context_str(incon, trans);
		free(trans);
	} else {
		*rcon = new_context_str(incon, range);
	}
	free(range);

#ifdef DEBUG
	struct timeval stopTime;
	gettimeofday(&stopTime, 0);
	long int ms;
	if (startTime.tv_usec > stopTime.tv_usec)
		ms = (stopTime.tv_sec - startTime.tv_sec - 1) * 1000 + (stopTime.tv_usec/1000 + 1000 - startTime.tv_usec/1000);
	else
		ms = (stopTime.tv_sec - startTime.tv_sec    ) * 1000 + (stopTime.tv_usec/1000        - startTime.tv_usec/1000);

	log_debug(" trans_context input='%s' output='%s in %ld ms'\n", incon, *rcon, ms);
#endif
	return 0;
}

int
untrans_context(const security_context_t incon, security_context_t *rcon) {
	char *raw = NULL;
	*rcon = NULL;

#ifdef DEBUG
	struct timeval startTime;
	gettimeofday(&startTime, 0);
#endif

	log_debug(" untrans_context incon = %s\n", incon);
	char *range = extract_range(incon);
	if (!range) return -1;
	log_debug(" untrans_context range = %s\n", range);

	domain_t *domain = domains;
	for (;domain; domain = domain->next) {
		raw = find_in_hashtable(range, domain, domain->trans_to_raw);
		if (raw) break;

		/* try split and translate */
		char *lrange = NULL, *urange = NULL;
		char *lraw = NULL, *uraw = NULL;
		char *dashp = strchr(range,'-');
		if (dashp) {
			*dashp = 0;
			lrange = range;
			urange = dashp+1;
		} else {
			raw = compute_raw_from_trans(range, domain);
			if (raw) {
				char *canonical = find_in_hashtable(raw, domain, domain->raw_to_trans);
				if (!canonical) {
					canonical = compute_trans_from_raw(raw, domain);
					if (canonical && strcmp(canonical, range))
						if (add_cache(domain, raw, canonical) < 0)
							return -1;
				}
				if (canonical)
					free(canonical);
				if (add_cache(domain, raw, range) < 0)
					return -1;
			} else {
				log_debug("untrans_context unable to compute raw context %s\n", range);
			}
		}

		if (lrange && urange) {
			lraw = find_in_hashtable(lrange, domain, domain->trans_to_raw);
			if (! lraw) {
				lraw = compute_raw_from_trans(lrange, domain);
				if (lraw) {
					char *canonical = find_in_hashtable(lraw, domain, domain->raw_to_trans);
					if (!canonical) {
						canonical = compute_trans_from_raw(lraw, domain);
						if (canonical)
							if (add_cache(domain, lraw, canonical) < 0)
								return -1;
					}
					if (canonical)
						free(canonical);
					if (add_cache(domain, lraw, lrange) < 0)
						return -1;
				} else {
					lraw = strdup(lrange);
					if (! lraw) {
						log_error("strdup failed %s", strerror(errno));
						return -1;
					}
				}
			}

			uraw = find_in_hashtable(urange, domain, domain->trans_to_raw);
			if (! uraw) {
				uraw = compute_raw_from_trans(urange, domain);
				if (uraw) {
					char *canonical = find_in_hashtable(uraw, domain, domain->raw_to_trans);
					if (!canonical) {
						canonical = compute_trans_from_raw(uraw, domain);
						if (canonical)
							if (add_cache(domain, uraw, canonical) < 0)
								return -1;
							}
					if (canonical)
						free(canonical);
					if (add_cache(domain, uraw, urange) < 0)
						return -1;
				} else {
					uraw = strdup(urange);
					if (! uraw) {
						log_error("strdup failed %s", strerror(errno));
						return -1;
					}
				}
			}


			if (strcmp(lraw, uraw) == 0) {
				if (asprintf(&raw, "%s", lraw) < 0) {
					log_error("asprintf failed %s", strerror(errno));
					return -1;
				}
			} else {
				if (asprintf(&raw, "%s-%s", lraw, uraw) < 0) {
					log_error("asprintf failed %s", strerror(errno));
					return -1;
				}
			}
			free(lraw);
			free(uraw);
			*dashp = '-';
			break;
		}
		if (dashp)
			*dashp = '-';
	}

	if (raw) {
		*rcon = new_context_str(incon, raw);
		free(raw);
	} else {
		*rcon = new_context_str(incon, range);
	}
	free(range);

#ifdef DEBUG
	struct timeval stopTime;
	gettimeofday(&stopTime, 0);
	long int ms;
	if (startTime.tv_usec > stopTime.tv_usec)
		ms = (stopTime.tv_sec - startTime.tv_sec - 1) * 1000 + (stopTime.tv_usec/1000 + 1000 - startTime.tv_usec/1000);
	else
		ms = (stopTime.tv_sec - startTime.tv_sec    ) * 1000 + (stopTime.tv_usec/1000        - startTime.tv_usec/1000);

	log_debug(" untrans_context input='%s' output='%s' n %ld ms\n", incon, *rcon, ms);
#endif
	return 0;
}

void
finish_context_translations(void) {
	while(domains) {
		domain_t *next = domains->next;
		destroy_domain(domains);
		domains = next;
	}
	while(sens_constraints) {
		sens_constraint_t *next = sens_constraints->next;
		destroy_sens_constraint(&sens_constraints, sens_constraints);
		sens_constraints = next;
	}
	while(cat_constraints) {
		cat_constraint_t *next = cat_constraints->next;
		destroy_cat_constraint(&cat_constraints, cat_constraints);
		cat_constraints = next;
	}
}

