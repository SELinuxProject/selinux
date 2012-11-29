/*
 * String representation support for classes and permissions.
 */
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <selinux/flask.h>
#include <selinux/av_permissions.h>
#include "selinux_internal.h"
#include "policy.h"
#include "mapping.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/* The following code looks complicated, but it really is not.  What it
   does is to generate two variables.  The first is basically a struct
   of arrays.  The second is the real array of structures which would
   have used string pointers.  But instead it now uses an offset value
   into the first structure.  Strings are accessed indirectly by an
   explicit addition of the string index and the base address of the
   structure with the strings (all type safe).  The advantage is that
   there are no relocations necessary in the array with the data as it
   would be the case with string pointers.  This has advantages at
   load time, the data section is smaller, and it is read-only.  */
#define L1(line) L2(line)
#define L2(line) str##line
static const union av_perm_to_string_data {
	struct {
#define S_(c, v, s) char L1(__LINE__)[sizeof(s)];
#include "av_perm_to_string.h"
#undef  S_
	};
	char str[0];
} av_perm_to_string_data = {
	{
#define S_(c, v, s) s,
#include "av_perm_to_string.h"
#undef  S_
	}
};
static const struct av_perm_to_string {
	uint16_t tclass;
	uint16_t nameidx;
	uint32_t value;
} av_perm_to_string[] = {
#define S_(c, v, s) { c, offsetof(union av_perm_to_string_data, L1(__LINE__)), v },
#include "av_perm_to_string.h"
#undef  S_
};

#undef L1
#undef L2

#define L1(line) L2(line)
#define L2(line) str##line
static const union class_to_string_data {
	struct {
#define S_(s) char L1(__LINE__)[sizeof(s)];
#include "class_to_string.h"
#undef  S_
	};
	char str[0];
} class_to_string_data = {
	{
#define S_(s) s,
#include "class_to_string.h"
#undef  S_
	}
};
static const uint16_t class_to_string[] = {
#define S_(s) offsetof(union class_to_string_data, L1(__LINE__)),
#include "class_to_string.h"
#undef  S_
};

#undef L1
#undef L2

static const union common_perm_to_string_data {
	struct {
#define L1(line) L2(line)
#define L2(line) str##line
#define S_(s) char L1(__LINE__)[sizeof(s)];
#define TB_(s)
#define TE_(s)
#include "common_perm_to_string.h"
#undef  S_
#undef L1
#undef L2
	};
	char str[0];
} common_perm_to_string_data = {
	{
#define S_(s) s,
#include "common_perm_to_string.h"
#undef  S_
#undef TB_
#undef TE_
	}
};
static const union common_perm_to_string {
	struct {
#define TB_(s) struct {
#define TE_(s) } s##_part;
#define S_(s) uint16_t L1(__LINE__)
#define L1(l) L2(l)
#define L2(l) field_##l;
#include "common_perm_to_string.h"
#undef TB_
#undef TE_
#undef S_
#undef L1
#undef L2
	};
	uint16_t data[0];
} common_perm_to_string = {
	{
#define TB_(s) {
#define TE_(s) },
#define S_(s) offsetof(union common_perm_to_string_data, L1(__LINE__)),
#define L1(line) L2(line)
#define L2(line) str##line
#include "common_perm_to_string.h"
#undef TB_
#undef TE_
#undef S_
#undef L1
#undef L2
	}
};

static const struct av_inherit {
	uint16_t tclass;
	uint16_t common_pts_idx;
	uint32_t common_base;
} av_inherit[] = {
#define S_(c, i, b) { c, offsetof(union common_perm_to_string, common_##i##_perm_to_string_part)/sizeof(uint16_t), b },
#include "av_inherit.h"
#undef S_
};

#define NCLASSES ARRAY_SIZE(class_to_string)
#define NVECTORS ARRAY_SIZE(av_perm_to_string)
#define MAXVECTORS 8*sizeof(access_vector_t)

static pthread_once_t once = PTHREAD_ONCE_INIT;

static int obj_class_compat;

static void init_obj_class_compat(void)
{
	char path[PATH_MAX];
	struct stat s;

	if (!selinux_mnt)
		return;

	snprintf(path,PATH_MAX,"%s/class",selinux_mnt);
	if (stat(path,&s) < 0)
		return;

	if (S_ISDIR(s.st_mode))
		obj_class_compat = 0;
}

struct discover_class_node {
	char *name;
	security_class_t value;
	char **perms;

	struct discover_class_node *next;
};

static struct discover_class_node *discover_class_cache = NULL;

static struct discover_class_node * get_class_cache_entry_name(const char *s)
{
	struct discover_class_node *node = discover_class_cache;

	for (; node != NULL && strcmp(s,node->name) != 0; node = node->next);

	return node;
}

static struct discover_class_node * get_class_cache_entry_value(security_class_t c)
{
	struct discover_class_node *node = discover_class_cache;

	for (; node != NULL && c != node->value; node = node->next);

	return node;
}

static struct discover_class_node * discover_class(const char *s)
{
	int fd, ret;
	char path[PATH_MAX];
	char buf[20];
	DIR *dir;
	struct dirent *dentry;
	size_t i;

	struct discover_class_node *node;

	if (!selinux_mnt) {
		errno = ENOENT;
		return NULL;
	}

	/* allocate a node */
	node = malloc(sizeof(struct discover_class_node));
	if (node == NULL)
		return NULL;

	/* allocate array for perms */
	node->perms = calloc(NVECTORS,sizeof(char*));
	if (node->perms == NULL)
		goto err1;

	/* load up the name */
	node->name = strdup(s);
	if (node->name == NULL)
		goto err2;

	/* load up class index */
	snprintf(path, sizeof path, "%s/class/%s/index", selinux_mnt,s);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		goto err3;

	memset(buf, 0, sizeof(buf));
	ret = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (ret < 0)
		goto err3;

	if (sscanf(buf, "%hu", &node->value) != 1)
		goto err3;

	/* load up permission indicies */
	snprintf(path, sizeof path, "%s/class/%s/perms",selinux_mnt,s);
	dir = opendir(path);
	if (dir == NULL)
		goto err3;

	dentry = readdir(dir);
	while (dentry != NULL) {
		unsigned int value;
		struct stat m;

		snprintf(path, sizeof path, "%s/class/%s/perms/%s", selinux_mnt,s,dentry->d_name);
		fd = open(path, O_RDONLY | O_CLOEXEC);
		if (fd < 0)
			goto err4;

		if (fstat(fd, &m) < 0) {
			close(fd);
			goto err4;
		}

		if (m.st_mode & S_IFDIR) {
			close(fd);
			dentry = readdir(dir);
			continue;
		}

		memset(buf, 0, sizeof(buf));
		ret = read(fd, buf, sizeof(buf) - 1);
		close(fd);
		if (ret < 0)
			goto err4;

		if (sscanf(buf, "%u", &value) != 1)
			goto err4;

		if (value == 0 || value > NVECTORS)
			goto err4;

		node->perms[value-1] = strdup(dentry->d_name);
		if (node->perms[value-1] == NULL)
			goto err4;

		dentry = readdir(dir);
	}
	closedir(dir);

	node->next = discover_class_cache;
	discover_class_cache = node;

	return node;

err4:
	closedir(dir);
	for (i=0; i<NVECTORS; i++)
		free(node->perms[i]);
err3:
	free(node->name);
err2:
	free(node->perms);
err1:
	free(node);
	return NULL;
}

static security_class_t string_to_security_class_compat(const char *s)
{
	unsigned int val;

	if (isdigit(s[0])) {
		val = atoi(s);
		if (val > 0 && val < NCLASSES)
			return map_class(val);
	} else {
		for (val = 0; val < NCLASSES; val++) {
			if (strcmp(s, (class_to_string_data.str
				       + class_to_string[val])) == 0)
				return map_class(val);
		}
	}

	errno = EINVAL;
	return 0;
}

static access_vector_t string_to_av_perm_compat(security_class_t kclass, const char *s)
{
	const uint16_t *common_pts_idx = 0;
	access_vector_t perm, common_base = 0;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(av_inherit); i++) {
		if (av_inherit[i].tclass == kclass) {
			common_pts_idx =
			    &common_perm_to_string.data[av_inherit[i].
							common_pts_idx];
			common_base = av_inherit[i].common_base;
			break;
		}
	}

	i = 0;
	perm = 1;
	while (perm < common_base) {
		if (strcmp
		    (s,
		     common_perm_to_string_data.str + common_pts_idx[i]) == 0)
			return perm;
		perm <<= 1;
		i++;
	}

	for (i = 0; i < NVECTORS; i++) {
		if ((av_perm_to_string[i].tclass == kclass) &&
		    (strcmp(s, (av_perm_to_string_data.str
				+ av_perm_to_string[i].nameidx)) == 0))
			return av_perm_to_string[i].value;
	}

	errno = EINVAL;
	return 0;
}

static const char *security_class_to_string_compat(security_class_t tclass)
{
	if (tclass > 0 && tclass < NCLASSES)
		return class_to_string_data.str + class_to_string[tclass];

	errno = EINVAL;
	return NULL;
}

static const char *security_av_perm_to_string_compat(security_class_t tclass,
				       access_vector_t av)
{
	const uint16_t *common_pts_idx = 0;
	access_vector_t common_base = 0;
	unsigned int i;

	if (!av) {
		errno = EINVAL;
		return NULL;
	}

	for (i = 0; i < ARRAY_SIZE(av_inherit); i++) {
		if (av_inherit[i].tclass == tclass) {
			common_pts_idx =
			    &common_perm_to_string.data[av_inherit[i].
							common_pts_idx];
			common_base = av_inherit[i].common_base;
			break;
		}
	}

	if (av < common_base) {
		i = 0;
		while (!(av & 1)) {
			av >>= 1;
			i++;
		}
		return common_perm_to_string_data.str + common_pts_idx[i];
	}

	for (i = 0; i < NVECTORS; i++) {
		if (av_perm_to_string[i].tclass == tclass &&
		    av_perm_to_string[i].value == av)
			return av_perm_to_string_data.str
				+ av_perm_to_string[i].nameidx;
	}

	errno = EINVAL;
	return NULL;
}

security_class_t string_to_security_class(const char *s)
{
	struct discover_class_node *node;

	__selinux_once(once, init_obj_class_compat);

	if (obj_class_compat)
		return string_to_security_class_compat(s);

	node = get_class_cache_entry_name(s);
	if (node == NULL) {
		node = discover_class(s);

		if (node == NULL) {
			errno = EINVAL;
			return 0;
		}
	}

	return map_class(node->value);
}

security_class_t mode_to_security_class(mode_t m) {

	if (S_ISREG(m))
		return string_to_security_class("file");
	if (S_ISDIR(m))
		return string_to_security_class("dir");
	if (S_ISCHR(m))
		return string_to_security_class("chr_file");
	if (S_ISBLK(m))
		return string_to_security_class("blk_file");
	if (S_ISFIFO(m))
		return string_to_security_class("fifo_file");
	if (S_ISLNK(m))
		return string_to_security_class("lnk_file");
	if (S_ISSOCK(m))
		return string_to_security_class("sock_file");

	errno=EINVAL;
	return 0;
}

access_vector_t string_to_av_perm(security_class_t tclass, const char *s)
{
	struct discover_class_node *node;
	security_class_t kclass = unmap_class(tclass);

	__selinux_once(once, init_obj_class_compat);

	if (obj_class_compat)
		return map_perm(tclass, string_to_av_perm_compat(kclass, s));

	node = get_class_cache_entry_value(kclass);
	if (node != NULL) {
		size_t i;
		for (i=0; i<MAXVECTORS && node->perms[i] != NULL; i++)
			if (strcmp(node->perms[i],s) == 0)
				return map_perm(tclass, 1<<i);
	}

	errno = EINVAL;
	return 0;
}

const char *security_class_to_string(security_class_t tclass)
{
	struct discover_class_node *node;

	tclass = unmap_class(tclass);

	__selinux_once(once, init_obj_class_compat);

	if (obj_class_compat)
		return security_class_to_string_compat(tclass);

	node = get_class_cache_entry_value(tclass);
	if (node == NULL)
		return security_class_to_string_compat(tclass);
	else
		return node->name;
}

const char *security_av_perm_to_string(security_class_t tclass,
				       access_vector_t av)
{
	struct discover_class_node *node;
	size_t i;

	av = unmap_perm(tclass, av);
	tclass = unmap_class(tclass);

	__selinux_once(once, init_obj_class_compat);

	if (obj_class_compat)
		return security_av_perm_to_string_compat(tclass,av);

	node = get_class_cache_entry_value(tclass);
	if (av && node)
		for (i = 0; i<MAXVECTORS; i++)
			if ((1<<i) & av)
				return node->perms[i];

	return security_av_perm_to_string_compat(tclass,av);
}

int security_av_string(security_class_t tclass, access_vector_t av, char **res)
{
	unsigned int i = 0;
	size_t len = 5;
	access_vector_t tmp = av;
	int rc = 0;
	const char *str;
	char *ptr;

	/* first pass computes the required length */
	while (tmp) {
		if (tmp & 1) {
			str = security_av_perm_to_string(tclass, av & (1<<i));
			if (str)
				len += strlen(str) + 1;
			else {
				rc = -1;
				errno = EINVAL;
				goto out;
			}
		}
		tmp >>= 1;
		i++;
	}

	*res = malloc(len);
	if (!*res) {
		rc = -1;
		goto out;
	}

	/* second pass constructs the string */
	i = 0;
	tmp = av;
	ptr = *res;

	if (!av) {
		sprintf(ptr, "null");
		goto out;
	}

	ptr += sprintf(ptr, "{ ");
	while (tmp) {
		if (tmp & 1)
			ptr += sprintf(ptr, "%s ", security_av_perm_to_string(
					       tclass, av & (1<<i)));
		tmp >>= 1;
		i++;
	}
	sprintf(ptr, "}");
out:
	return rc;
}

void print_access_vector(security_class_t tclass, access_vector_t av)
{
	const char *permstr;
	access_vector_t bit = 1;

	if (av == 0) {
		printf(" null");
		return;
	}

	printf(" {");

	while (av) {
		if (av & bit) {
			permstr = security_av_perm_to_string(tclass, bit);
			if (!permstr)
				break;
			printf(" %s", permstr);
			av &= ~bit;
		}
		bit <<= 1;
	}

	if (av)
		printf(" 0x%x", av);
	printf(" }");
}
