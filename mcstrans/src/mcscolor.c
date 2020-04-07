#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <ctype.h>
#include <alloca.h>
#include <fnmatch.h>
#include <syslog.h>
#include <selinux/selinux.h>
#include <selinux/context.h>
#include "mcstrans.h"

/* Define data structures */
typedef struct secolor {
	uint32_t fg;
	uint32_t bg;
} secolor_t;

typedef struct semnemonic {
	char *name;
	uint32_t color;
	struct semnemonic *next;
} semnemonic_t;

typedef struct setab {
	char *pattern;
	secolor_t color;
	struct setab *next;
} setab_t;

#define COLOR_USER	0
#define COLOR_ROLE	1
#define COLOR_TYPE	2
#define COLOR_RANGE	3
#define N_COLOR		4

#define AUX_RULE_COLOR "color"
static const char *rules[] = { "user", "role", "type", "range" };

static setab_t *clist[N_COLOR];
static setab_t *cend[N_COLOR];
static semnemonic_t *mnemonics;

static char *my_context;

void finish_context_colors(void) {
	setab_t *cur, *next;
	semnemonic_t *ptr;
	unsigned i;

	for (i = 0; i < N_COLOR; i++) {
		cur = clist[i];
		while(cur) {
			next = cur->next;
			free(cur->pattern);
			free(cur);
			cur = next;
		}
		clist[i] = cend[i] = NULL;
	}

	ptr = mnemonics;
	while (ptr) {
		mnemonics = ptr->next;
		free(ptr->name);
		free(ptr);
		ptr = mnemonics;
	}
	mnemonics = NULL;

	freecon(my_context);
	my_context = NULL;
}

static int check_dominance(const char *pattern, const char *raw) {
	char *ctx;
	context_t con;
	struct av_decision avd;
	int rc = -1;
	context_t my_tmp;
	const char *raw_range;
	security_class_t context_class = string_to_security_class("context");
	access_vector_t context_contains_perm = string_to_av_perm(context_class, "contains");

	con = context_new(raw);
	if (!con)
		return -1;
	raw_range = context_range_get(con);

	my_tmp = context_new(my_context);
	if (!my_tmp) {
		context_free(con);
		return -1;
	}

	ctx = NULL;
	if (context_range_set(my_tmp, pattern))
		goto out;
	ctx = strdup(context_str(my_tmp));
	if (!ctx)
		goto out;

	if (context_range_set(my_tmp, raw_range))
		goto out;
	raw = context_str(my_tmp);
	if (!raw)
		goto out;

	rc = security_compute_av_raw(ctx, raw, context_class, context_contains_perm, &avd);
	if (rc)
		goto out;

	rc = (context_contains_perm & avd.allowed) != context_contains_perm;
out:
	free(ctx);
	context_free(my_tmp);
	context_free(con);
	return rc;
}

static const secolor_t *find_color(int idx, const char *component,
				   const char *raw) {
	setab_t *ptr = clist[idx];

	if (idx == COLOR_RANGE) {
		if (!raw) {
			return NULL;
		}
	} else if (!component) {
		return NULL;
	}

	while (ptr) {
		if (idx == COLOR_RANGE) {
		    if (check_dominance(ptr->pattern, raw) == 0)
			return &ptr->color;
		} else {
		    if (fnmatch(ptr->pattern, component, 0) == 0)
			return &ptr->color;
		}
		ptr = ptr->next;
	}

	return NULL;
}

static int add_secolor(int idx, char *pattern, uint32_t fg, uint32_t bg) {
	setab_t *cptr;

	cptr = calloc(1, sizeof(setab_t));
	if (!cptr) return -1;

	cptr->pattern = strdup(pattern);
	if (!cptr->pattern) {
		free(cptr);
		return -1;
	}

	cptr->color.fg = fg & 0xffffff;
	cptr->color.bg = bg & 0xffffff;

	if (cend[idx]) {
		cend[idx]->next = cptr;
		cend[idx] = cptr;
	} else {
		clist[idx] = cptr;
		cend[idx] = cptr;
	}
	return 0;
}

static int find_mnemonic(const char *name, uint32_t *retval)
{
	semnemonic_t *ptr;

	if (*name == '#')
		return sscanf(name, "#%x", retval) == 1 ? 0 : -1;

	ptr = mnemonics;
	while (ptr) {
		if (!strcmp(ptr->name, name)) {
			*retval = ptr->color;
			return 0;
		}
		ptr = ptr->next;
	}

	return -1;
}

static int add_mnemonic(const char *name, uint32_t color)
{
	semnemonic_t *ptr = malloc(sizeof(semnemonic_t));
	if (!ptr)
		return -1;

	ptr->color = color;
	ptr->name = strdup(name);
	if (!ptr->name) {
		free(ptr);
		return -1;
	}

	ptr->next = mnemonics;
	mnemonics = ptr;
	return 0;
}


/* Process line from color file.
   May modify the data pointed to by the buffer parameter */
static int process_color(char *buffer, int line) {
	char rule[10], pat[256], f[256], b[256];
	uint32_t i, fg, bg;
	int ret;

	while(isspace(*buffer))
		buffer++;
	if(buffer[0] == '#' || buffer[0] == '\0') return 0;

	ret = sscanf(buffer, "%8s %255s = %255s %255s", rule, pat, f, b);
	if (ret == 4) {
		if (find_mnemonic(f, &fg) == 0 && find_mnemonic(b, &bg) == 0)
			for (i = 0; i < N_COLOR; i++)
				if (!strcmp(rule, rules[i]))
					return add_secolor(i, pat, fg, bg);
	}
	else if (ret == 3) {
		if (!strcmp(rule, AUX_RULE_COLOR)) {
			if (sscanf(f, "#%x", &fg) == 1)
				return add_mnemonic(pat, fg);
		}
	}

	syslog(LOG_WARNING, "Line %d of secolors file is invalid.", line);
	return 0;
}

/* Read in color file.
 */
int init_colors(void) {
	FILE *cfg = NULL;
	size_t size = 0;
	char *buffer = NULL;
	int line = 0;

	getcon(&my_context);

	cfg = fopen(selinux_colors_path(), "r");
	if (!cfg) return 1;

	__fsetlocking(cfg, FSETLOCKING_BYCALLER);
	while (getline(&buffer, &size, cfg) > 0) {
		if( process_color(buffer, ++line) < 0 ) break;
	}
	free(buffer);

	fclose(cfg);
	return 0;
}

static const unsigned precedence[N_COLOR][N_COLOR - 1] = {
	{ COLOR_ROLE, COLOR_TYPE, COLOR_RANGE },
	{ COLOR_USER, COLOR_TYPE, COLOR_RANGE },
	{ COLOR_USER, COLOR_ROLE, COLOR_RANGE },
	{ COLOR_USER, COLOR_ROLE, COLOR_TYPE },
};

static const secolor_t default_color = { 0x000000, 0xffffff };

static int parse_components(context_t con, char **components) {
	components[COLOR_USER] = (char *)context_user_get(con);
	components[COLOR_ROLE] = (char *)context_role_get(con);
	components[COLOR_TYPE] = (char *)context_type_get(con);
	components[COLOR_RANGE] = (char *)context_range_get(con);

	return 0;
}

/* Look up colors.
 */
int raw_color(const char *raw, char **color_str) {
#define CHARS_PER_COLOR 16
	context_t con;
	uint32_t i, j, mask = 0;
	const secolor_t *items[N_COLOR];
	char *result, *components[N_COLOR];
	char buf[CHARS_PER_COLOR + 1];
	size_t result_size = (N_COLOR * CHARS_PER_COLOR) + 1;
	int rc = -1;

	if (!color_str || *color_str) {
		return -1;
	}

	/* parse context and allocate memory */
	con = context_new(raw);
	if (!con)
		return -1;
	if (parse_components(con, components) < 0)
		goto out;

	result = malloc(result_size);
	if (!result)
		goto out;
	result[0] = '\0';

	/* find colors for which we have a match */
	for (i = 0; i < N_COLOR; i++) {
		items[i] = find_color(i, components[i], raw);
		if (items[i])
			mask |= (1 << i);
	}
	if (mask == 0) {
		items[0] = &default_color;
		mask = 1;
	}

	/* propagate colors according to the precedence rules */
	for (i = 0; i < N_COLOR; i++)
		if (!(mask & (1 << i)))
			for (j = 0; j < N_COLOR - 1; j++)
				if (mask & (1 << precedence[i][j])) {
					items[i] = items[precedence[i][j]];
					break;
				}

	/* print results into a big long string */
	for (i = 0; i < N_COLOR; i++) {
		snprintf(buf, sizeof(buf), "#%06x #%06x ",
			 items[i]->fg, items[i]->bg);
		strncat(result, buf, result_size-1);
	}

	*color_str = result;
	rc = 0;
out:
	context_free(con);

	return rc;
}
