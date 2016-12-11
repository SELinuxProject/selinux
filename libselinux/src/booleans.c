/*
 * Author: Karl MacMillan <kmacmillan@tresys.com>
 *
 * Modified:  
 *   Dan Walsh <dwalsh@redhat.com> - Added security_load_booleans().
 */

#ifndef DISABLE_BOOL

#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <unistd.h>
#include <fnmatch.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>

#include "selinux_internal.h"
#include "policy.h"

#define SELINUX_BOOL_DIR "/booleans/"

static int filename_select(const struct dirent *d)
{
	if (d->d_name[0] == '.'
	    && (d->d_name[1] == '\0'
		|| (d->d_name[1] == '.' && d->d_name[2] == '\0')))
		return 0;
	return 1;
}

int security_get_boolean_names(char ***names, int *len)
{
	char path[PATH_MAX];
	int i, rc;
	struct dirent **namelist;
	char **n;

	if (!len || names == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (!selinux_mnt) {
		errno = ENOENT;
		return -1;
	}

	snprintf(path, sizeof path, "%s%s", selinux_mnt, SELINUX_BOOL_DIR);
	*len = scandir(path, &namelist, &filename_select, alphasort);
	if (*len <= 0) {
		return -1;
	}

	n = (char **)malloc(sizeof(char *) * *len);
	if (!n) {
		rc = -1;
		goto bad;
	}

	for (i = 0; i < *len; i++) {
		n[i] = strdup(namelist[i]->d_name);
		if (!n[i]) {
			rc = -1;
			goto bad_freen;
		}
	}
	rc = 0;
	*names = n;
      out:
	for (i = 0; i < *len; i++) {
		free(namelist[i]);
	}
	free(namelist);
	return rc;
      bad_freen:
	for (--i; i >= 0; --i)
		free(n[i]);
	free(n);
      bad:
	goto out;
}

char *selinux_boolean_sub(const char *name)
{
	char *sub = NULL;
	char *line_buf = NULL;
	size_t line_len;
	FILE *cfg;

	if (!name)
		return NULL;

	cfg = fopen(selinux_booleans_subs_path(), "re");
	if (!cfg)
		goto out;

	while (getline(&line_buf, &line_len, cfg) != -1) {
		char *ptr;
		char *src = line_buf;
		char *dst;
		while (*src && isspace(*src))
			src++;
		if (!*src)
			continue;
		if (src[0] == '#')
			continue;

		ptr = src;
		while (*ptr && !isspace(*ptr))
			ptr++;
		*ptr++ = '\0';
		if (strcmp(src, name) != 0)
			continue;

		dst = ptr;
		while (*dst && isspace(*dst))
			dst++;
		if (!*dst)
			continue;
		ptr=dst;
		while (*ptr && !isspace(*ptr))
			ptr++;
		*ptr='\0';

		sub = strdup(dst);

		break;
	}
	free(line_buf);
	fclose(cfg);
out:
	if (!sub)
		sub = strdup(name);
	return sub;
}

static int bool_open(const char *name, int flag) {
	char *fname = NULL;
	char *alt_name = NULL;
	int len;
	int fd = -1;
	int ret;
	char *ptr;

	if (!name) {
		errno = EINVAL;
		return -1;
	}

	/* note the 'sizeof' gets us enough room for the '\0' */
	len = strlen(name) + strlen(selinux_mnt) + sizeof(SELINUX_BOOL_DIR);
	fname = malloc(sizeof(char) * len);
	if (!fname)
		return -1;

	ret = snprintf(fname, len, "%s%s%s", selinux_mnt, SELINUX_BOOL_DIR, name);
	if (ret < 0)
		goto out;
	assert(ret < len);

	fd = open(fname, flag);
	if (fd >= 0 || errno != ENOENT)
		goto out;

	alt_name = selinux_boolean_sub(name);
	if (!alt_name)
		goto out;

	/* note the 'sizeof' gets us enough room for the '\0' */
	len = strlen(alt_name) + strlen(selinux_mnt) + sizeof(SELINUX_BOOL_DIR);
	ptr = realloc(fname, len);
	if (!ptr)
		goto out;
	fname = ptr;

	ret = snprintf(fname, len, "%s%s%s", selinux_mnt, SELINUX_BOOL_DIR, alt_name);
	if (ret < 0)
		goto out;
	assert(ret < len);

	fd = open(fname, flag);
out:
	free(fname);
	free(alt_name);

	return fd;
}

#define STRBUF_SIZE 3
static int get_bool_value(const char *name, char **buf)
{
	int fd, len;
	int errno_tmp;

	if (!selinux_mnt) {
		errno = ENOENT;
		return -1;
	}

	*buf = malloc(sizeof(char) * (STRBUF_SIZE + 1));
	if (!*buf)
		return -1;

	(*buf)[STRBUF_SIZE] = 0;

	fd = bool_open(name, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		goto out_err;

	len = read(fd, *buf, STRBUF_SIZE);
	errno_tmp = errno;
	close(fd);
	errno = errno_tmp;
	if (len != STRBUF_SIZE)
		goto out_err;

	return 0;
out_err:
	free(*buf);
	return -1;
}

int security_get_boolean_pending(const char *name)
{
	char *buf;
	int val;

	if (get_bool_value(name, &buf))
		return -1;

	if (atoi(&buf[1]))
		val = 1;
	else
		val = 0;
	free(buf);
	return val;
}

int security_get_boolean_active(const char *name)
{
	char *buf;
	int val;

	if (get_bool_value(name, &buf))
		return -1;

	buf[1] = '\0';
	if (atoi(buf))
		val = 1;
	else
		val = 0;
	free(buf);
	return val;
}

int security_set_boolean(const char *name, int value)
{
	int fd, ret;
	char buf[2];

	if (!selinux_mnt) {
		errno = ENOENT;
		return -1;
	}
	if (value < 0 || value > 1) {
		errno = EINVAL;
		return -1;
	}

	fd = bool_open(name, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;

	if (value)
		buf[0] = '1';
	else
		buf[0] = '0';
	buf[1] = '\0';

	ret = write(fd, buf, 2);
	close(fd);

	if (ret > 0)
		return 0;
	else
		return -1;
}

int security_commit_booleans(void)
{
	int fd, ret;
	char buf[2];
	char path[PATH_MAX];

	if (!selinux_mnt) {
		errno = ENOENT;
		return -1;
	}

	snprintf(path, sizeof path, "%s/commit_pending_bools", selinux_mnt);
	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;

	buf[0] = '1';
	buf[1] = '\0';

	ret = write(fd, buf, 2);
	close(fd);

	if (ret > 0)
		return 0;
	else
		return -1;
}

static char *strtrim(char *dest, char *source, int size)
{
	int i = 0;
	char *ptr = source;
	i = 0;
	while (isspace(*ptr) && i < size) {
		ptr++;
		i++;
	}
	strncpy(dest, ptr, size);
	for (i = strlen(dest) - 1; i > 0; i--) {
		if (!isspace(dest[i]))
			break;
	}
	dest[i + 1] = '\0';
	return dest;
}
static int process_boolean(char *buffer, char *name, int namesize, int *val)
{
	char name1[BUFSIZ];
	char *ptr = NULL;
	char *tok;

	/* Skip spaces */
	while (isspace(buffer[0]))
		buffer++;
	/* Ignore comments */
	if (buffer[0] == '#')
		return 0;

	tok = strtok_r(buffer, "=", &ptr);
	if (!tok) {
		errno = EINVAL;
		return -1;
	}
	strncpy(name1, tok, BUFSIZ - 1);
	strtrim(name, name1, namesize - 1);

	tok = strtok_r(NULL, "\0", &ptr);
	if (!tok) {
		errno = EINVAL;
		return -1;
	}

	while (isspace(*tok))
		tok++;

	*val = -1;
	if (isdigit(tok[0]))
		*val = atoi(tok);
	else if (!strncasecmp(tok, "true", sizeof("true") - 1))
		*val = 1;
	else if (!strncasecmp(tok, "false", sizeof("false") - 1))
		*val = 0;
	if (*val != 0 && *val != 1) {
		errno = EINVAL;
		return -1;
	}
	return 1;
}
static int save_booleans(size_t boolcnt, SELboolean * boollist)
{
	ssize_t len;
	size_t i;
	char outbuf[BUFSIZ];
	char *inbuf = NULL;

	/* Open file */
	const char *bool_file = selinux_booleans_path();
	char local_bool_file[PATH_MAX];
	char tmp_bool_file[PATH_MAX];
	FILE *boolf;
	int fd;
	int *used = (int *)malloc(sizeof(int) * boolcnt);
	if (!used) {
		return -1;
	}
	/* zero out used field */
	for (i = 0; i < boolcnt; i++)
		used[i] = 0;

	snprintf(tmp_bool_file, sizeof(tmp_bool_file), "%s.XXXXXX", bool_file);
	fd = mkstemp(tmp_bool_file);
	if (fd < 0) {
		free(used);
		return -1;
	}

	snprintf(local_bool_file, sizeof(local_bool_file), "%s.local",
		 bool_file);
	boolf = fopen(local_bool_file, "re");
	if (boolf != NULL) {
		ssize_t ret;
		size_t size = 0;
		int val;
		char boolname[BUFSIZ];
		char *buffer;
		inbuf = NULL;
		__fsetlocking(boolf, FSETLOCKING_BYCALLER);
		while ((len = getline(&inbuf, &size, boolf)) > 0) {
			buffer = strdup(inbuf);
			if (!buffer)
				goto close_remove_fail;
			ret =
			    process_boolean(inbuf, boolname, sizeof(boolname),
					    &val);
			if (ret != 1) {
				ret = write(fd, buffer, len);
				free(buffer);
				if (ret != len)
					goto close_remove_fail;
			} else {
				free(buffer);
				for (i = 0; i < boolcnt; i++) {
					if (strcmp(boollist[i].name, boolname)
					    == 0) {
						snprintf(outbuf, sizeof(outbuf),
							 "%s=%d\n", boolname,
							 boollist[i].value);
						len = strlen(outbuf);
						used[i] = 1;
						if (write(fd, outbuf, len) !=
						    len)
							goto close_remove_fail;
						else
							break;
					}
				}
				if (i == boolcnt) {
					snprintf(outbuf, sizeof(outbuf),
						 "%s=%d\n", boolname, val);
					len = strlen(outbuf);
					if (write(fd, outbuf, len) != len)
						goto close_remove_fail;
				}
			}
			free(inbuf);
			inbuf = NULL;
		}
		fclose(boolf);
	}

	for (i = 0; i < boolcnt; i++) {
		if (used[i] == 0) {
			snprintf(outbuf, sizeof(outbuf), "%s=%d\n",
				 boollist[i].name, boollist[i].value);
			len = strlen(outbuf);
			if (write(fd, outbuf, len) != len) {
			      close_remove_fail:
				free(inbuf);
				close(fd);
			      remove_fail:
				unlink(tmp_bool_file);
				free(used);
				return -1;
			}
		}

	}
	if (fchmod(fd, S_IRUSR | S_IWUSR) != 0)
		goto close_remove_fail;
	close(fd);
	if (rename(tmp_bool_file, local_bool_file) != 0)
		goto remove_fail;

	free(used);
	return 0;
}
static void rollback(SELboolean * boollist, int end)
{
	int i;

	for (i = 0; i < end; i++)
		security_set_boolean(boollist[i].name,
				     security_get_boolean_active(boollist[i].
								 name));
}

int security_set_boolean_list(size_t boolcnt, SELboolean * boollist,
			      int permanent)
{

	size_t i;
	for (i = 0; i < boolcnt; i++) {
		if (security_set_boolean(boollist[i].name, boollist[i].value)) {
			rollback(boollist, i);
			return -1;
		}
	}

	/* OK, let's do the commit */
	if (security_commit_booleans()) {
		return -1;
	}

	if (permanent)
		return save_booleans(boolcnt, boollist);

	return 0;
}
int security_load_booleans(char *path)
{
	FILE *boolf;
	char *inbuf;
	char localbools[BUFSIZ];
	size_t len = 0, errors = 0;
	int val;
	char name[BUFSIZ];

	boolf = fopen(path ? path : selinux_booleans_path(), "re");
	if (boolf == NULL)
		goto localbool;

	__fsetlocking(boolf, FSETLOCKING_BYCALLER);
	while (getline(&inbuf, &len, boolf) > 0) {
		int ret = process_boolean(inbuf, name, sizeof(name), &val);
		if (ret == -1)
			errors++;
		if (ret == 1)
			if (security_set_boolean(name, val) < 0) {
				errors++;
			}
	}
	fclose(boolf);
      localbool:
	snprintf(localbools, sizeof(localbools), "%s.local",
		 (path ? path : selinux_booleans_path()));
	boolf = fopen(localbools, "re");

	if (boolf != NULL) {
		int ret;
		__fsetlocking(boolf, FSETLOCKING_BYCALLER);
		while (getline(&inbuf, &len, boolf) > 0) {
			ret = process_boolean(inbuf, name, sizeof(name), &val);
			if (ret == -1)
				errors++;
			if (ret == 1)
				if (security_set_boolean(name, val) < 0) {
					errors++;
				}
		}
		fclose(boolf);
	}
	if (security_commit_booleans() < 0)
		return -1;

	if (errors)
		errno = EINVAL;
	return errors ? -1 : 0;
}

#else

#include <stdlib.h>
#include "selinux_internal.h"

int security_set_boolean_list(size_t boolcnt __attribute__((unused)),
	SELboolean * boollist __attribute__((unused)),
	int permanent __attribute__((unused)))
{
	return -1;
}

int security_load_booleans(char *path __attribute__((unused)))
{
	return -1;
}

int security_get_boolean_names(char ***names __attribute__((unused)),
	int *len __attribute__((unused)))
{
	return -1;
}

int security_get_boolean_pending(const char *name __attribute__((unused)))
{
	return -1;
}

int security_get_boolean_active(const char *name __attribute__((unused)))
{
	return -1;
}

int security_set_boolean(const char *name __attribute__((unused)),
	int value __attribute__((unused)))
{
	return -1;
}

int security_commit_booleans(void)
{
	return -1;
}

char *selinux_boolean_sub(const char *name __attribute__((unused)))
{
	return NULL;
}
#endif

hidden_def(security_get_boolean_names)
hidden_def(selinux_boolean_sub)
hidden_def(security_get_boolean_active)
hidden_def(security_set_boolean)
hidden_def(security_commit_booleans)
