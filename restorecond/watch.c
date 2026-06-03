#define _GNU_SOURCE
#include <sys/inotify.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <syslog.h>
#include "restore.h"
#include <glob.h>
#include <libgen.h>
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <dirent.h>
#include <selinux/selinux.h>
#include "restorecond.h"
#include "stringslist.h"
#include "utmpwatcher.h"

#ifndef GLOB_TILDE
#define GLOB_TILDE 0
#endif

#ifndef GLOB_BRACE
#define GLOB_BRACE 0
#endif

/* size of the event structure, not counting name */
#define EVENT_SIZE (sizeof(struct inotify_event))
/* reasonable guess as to size of 1024 events */
#define BUF_LEN (1024 * (EVENT_SIZE + 16))

struct watchList {
	struct watchList *next;
	int wd;
	char *dir;
	struct stringsList *files;
};
struct watchList *firstDir = NULL;

int watch_list_isempty(void)
{
	return firstDir == NULL;
}

static int open_final(int dfd, const char *name, struct stat *sb)
{
	int fd;

	if (name)
		fd = openat(dfd, name, O_PATH | O_NOFOLLOW | O_CLOEXEC);
	else
		fd = fcntl(dfd, F_DUPFD_CLOEXEC, 0);
	if (fd < 0)
		return -1;

	if (fstat(fd, sb) < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

static int safe_open(const char *path, struct stat *sb)
{
	char *copy, *cur, *slash;
	int dfd, nfd;

	if (!path || path[0] == '\0') {
		errno = ENOENT;
		return -1;
	}

	copy = strdup(path);
	if (!copy)
		return -1;

	if (copy[0] == '/') {
		dfd = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC);
		cur = copy + 1;
	} else {
		dfd = open(".", O_PATH | O_DIRECTORY | O_CLOEXEC);
		cur = copy;
	}
	if (dfd < 0) {
		free(copy);
		return -1;
	}

	while (*cur == '/')
		cur++;

	while (*cur != '\0') {
		slash = strchr(cur, '/');
		if (slash) {
			*slash = '\0';
			char *next = slash + 1;
			while (*next == '/')
				next++;
			if (*next != '\0') {
				nfd = openat(dfd, cur,
					     O_PATH | O_NOFOLLOW | O_DIRECTORY |
						     O_CLOEXEC);
				close(dfd);
				if (nfd < 0) {
					free(copy);
					return -1;
				}
				dfd = nfd;
				cur = next;
				continue;
			}
		}

		nfd = open_final(dfd, cur, sb);
		close(dfd);
		free(copy);
		return nfd;
	}

	nfd = open_final(dfd, NULL, sb);
	close(dfd);
	free(copy);
	return nfd;
}

static void *nofollow_opendir(const char *name)
{
	struct stat sb;
	int fd, rdfd;

	fd = safe_open(name, &sb);
	if (fd < 0)
		return NULL;

	if (!S_ISDIR(sb.st_mode)) {
		close(fd);
		errno = ENOTDIR;
		return NULL;
	}

	rdfd = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	close(fd);
	if (rdfd < 0)
		return NULL;
	return fdopendir(rdfd);
}

static struct dirent *nofollow_readdir(void *d)
{
	return readdir((DIR *)d);
}

static void nofollow_closedir(void *d)
{
	closedir((DIR *)d);
}

static int nofollow_lstat(const char *path, struct stat *sb)
{
	return lstat(path, sb);
}

void watch_list_add(int fd, const char *path)
{
	struct watchList *ptr = NULL;
	size_t i = 0;
	struct watchList *prev = NULL;
	glob_t globbuf;
	char *xb = strdup(path);
	if (!xb)
		exitApp("Out of Memory");
	char *xd = strdup(path);
	if (!xd)
		exitApp("Out of Memory");
	char *file = basename(xb);
	char *dir = dirname(xd);
	ptr = firstDir;
	int len;

	memset(&globbuf, 0, sizeof(globbuf));
	globbuf.gl_opendir = nofollow_opendir;
	globbuf.gl_readdir = nofollow_readdir;
	globbuf.gl_closedir = nofollow_closedir;
	globbuf.gl_lstat = nofollow_lstat;
	globbuf.gl_stat = nofollow_lstat; /* never follow symlinks */
	if (glob(path, GLOB_TILDE | GLOB_PERIOD | GLOB_ALTDIRFUNC, NULL,
		 &globbuf) >= 0) {
		for (i = 0; i < globbuf.gl_pathc; i++) {
			struct stat sb;
			const char *p = globbuf.gl_pathv[i];

			len = strlen(p) - 2;
			if (len > 0 && strcmp(&p[len--], "/.") == 0)
				continue;
			if (len > 0 && strcmp(&p[len], "/..") == 0)
				continue;
			if (lstat(p, &sb) == 0 && S_ISREG(sb.st_mode) &&
			    sb.st_nlink > 1)
				continue;
			selinux_restorecon(p, r_opts.restorecon_flags);
		}
		globfree(&globbuf);
	}

	while (ptr != NULL) {
		if (strcmp(dir, ptr->dir) == 0) {
			strings_list_add(&ptr->files, file);
			goto end;
		}
		prev = ptr;
		ptr = ptr->next;
	}
	ptr = calloc(1, sizeof(struct watchList));

	if (!ptr)
		exitApp("Out of Memory");

	ptr->wd = inotify_add_watch(fd, dir,
				    IN_CREATE | IN_MOVED_TO | IN_DONT_FOLLOW);
	if (ptr->wd == -1) {
		free(ptr);
		if (!run_as_user)
			syslog(LOG_ERR, "Unable to watch (%s) %s\n", path,
			       strerror(errno));
		goto end;
	}

	ptr->dir = strdup(dir);
	if (!ptr->dir)
		exitApp("Out of Memory");

	strings_list_add(&ptr->files, file);
	if (prev)
		prev->next = ptr;
	else
		firstDir = ptr;

	if (debug_mode)
		printf("%d: Dir=%s, File=%s\n", ptr->wd, ptr->dir, file);

end:
	free(xb);
	free(xd);
	return;
}

/*
   A file was in a direcroty has been created. This function checks to
   see if it is one that we are watching.
*/

int watch_list_find(int wd, const char *file)
{
	struct watchList *ptr = NULL;

	ptr = firstDir;

	if (debug_mode)
		printf("%d: File=%s\n", wd, file);
	while (ptr != NULL) {
		if (ptr->wd == wd) {
			int exact = 0;
			if (strings_list_find(ptr->files, file, &exact) == 0) {
				char *path = NULL;
				if (asprintf(&path, "%s/%s", ptr->dir, file) <
				    0)
					exitApp("Error allocating memory.");

				selinux_restorecon(path,
						   r_opts.restorecon_flags);
				free(path);
				return 0;
			}
			if (debug_mode)
				strings_list_print(ptr->files);

			/* Not found in this directory */
			return -1;
		}
		ptr = ptr->next;
	}
	/* Did not find a directory */
	return -1;
}

void watch_list_free(int fd)
{
	struct watchList *ptr = NULL;
	struct watchList *prev = NULL;
	ptr = firstDir;

	while (ptr != NULL) {
		inotify_rm_watch(fd, ptr->wd);
		strings_list_free(ptr->files);
		free(ptr->dir);
		prev = ptr;
		ptr = ptr->next;
		free(prev);
	}
	firstDir = NULL;
}

/*
   Inotify watch loop
*/
int watch(int fd, const char *watch_file)
{
	char buf[BUF_LEN];
	int len, i = 0;
	if (firstDir == NULL)
		return 0;

	len = read(fd, buf, BUF_LEN);
	if (len < 0) {
		if (terminate == 0) {
			syslog(LOG_ERR, "Read error (%s)", strerror(errno));
			return 0;
		}
		syslog(LOG_INFO, "terminated");
		return -1;
	} else if (!len)
		/* BUF_LEN too small? */
		return -1;
	while (i < len) {
		struct inotify_event *event;
		event = (struct inotify_event *)&buf[i];
		if (debug_mode)
			printf("wd=%d mask=%u cookie=%u len=%u\n", event->wd,
			       event->mask, event->cookie, event->len);
		if (event->mask & ~IN_IGNORED) {
			if (event->wd == master_wd)
				read_config(fd, watch_file);
			else {
				switch (utmpwatcher_handle(fd, event->wd)) {
				case -1: /* Message was not for utmpwatcher */
					if (event->len)
						watch_list_find(event->wd,
								event->name);
					break;
				case 1: /* utmp has changed need to reload */
					read_config(fd, watch_file);
					break;

				default: /* No users logged in or out */
					break;
				}
			}
		}

		i += EVENT_SIZE + event->len;
	}
	return 0;
}

static void process_config(int fd, FILE *cfg)
{
	char *line_buf = NULL;
	size_t len = 0;

	while (getline(&line_buf, &len, cfg) > 0) {
		char *buffer = line_buf;
		while (isspace(*buffer))
			buffer++;
		if (buffer[0] == '#')
			continue;
		int l = strlen(buffer) - 1;
		if (l <= 0)
			continue;
		buffer[l] = 0;
		if (buffer[0] == '~') {
			if (run_as_user) {
				char *ptr = NULL;
				if (asprintf(&ptr, "%s%s", homedir,
					     &buffer[1]) < 0)
					exitApp("Error allocating memory.");

				watch_list_add(fd, ptr);
				free(ptr);
			} else {
				utmpwatcher_add(fd, &buffer[1]);
			}
		} else {
			watch_list_add(fd, buffer);
		}
	}
	free(line_buf);
}

/*
   Read config file ignoring Comment lines
   Files specified one per line.  Files with "~" will be expanded to the logged in users
   homedirs.
*/

void read_config(int fd, const char *watch_file_path)
{
	FILE *cfg = NULL;
	if (debug_mode)
		printf("Read Config\n");

	watch_list_free(fd);

	cfg = fopen(watch_file_path, "r");
	if (!cfg) {
		perror(watch_file_path);
		exitApp("Error reading config file");
	}
	process_config(fd, cfg);
	fclose(cfg);

	inotify_rm_watch(fd, master_wd);
	master_wd =
		inotify_add_watch(fd, watch_file_path,
				  IN_MOVED_FROM | IN_MODIFY | IN_DONT_FOLLOW);
	if (master_wd == -1)
		exitApp("Error watching config file.");
}
