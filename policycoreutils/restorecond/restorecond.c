/*
 * restorecond
 *
 * Copyright (C) 2006-2009 Red Hat 
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
.* 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA     
 * 02111-1307  USA
 *
 * Authors:  
 *   Dan Walsh <dwalsh@redhat.com>
 *
*/

/* 
 * PURPOSE:
 * This daemon program watches for the creation of files listed in a config file
 * and makes sure that there security context matches the systems defaults
 *
 * USAGE:
 * restorecond [-d] [-v]
 * 
 * -d   Run in debug mode
 * -v   Run in verbose mode (Report missing files)
 *
 * EXAMPLE USAGE:
 * restorecond
 *
 */

#define _GNU_SOURCE
#include <sys/inotify.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <limits.h>
#include <fcntl.h>

#include "restorecond.h"
#include "stringslist.h"
#include "utmpwatcher.h"

extern char *dirname(char *path);
static int master_fd = -1;
static int master_wd = -1;
static int terminate = 0;

#include <selinux/selinux.h>
#include <utmp.h>

/* size of the event structure, not counting name */
#define EVENT_SIZE  (sizeof (struct inotify_event))
/* reasonable guess as to size of 1024 events */
#define BUF_LEN        (1024 * (EVENT_SIZE + 16))

static int debug_mode = 0;
static int verbose_mode = 0;

static void restore(const char *filename, int exact);

struct watchList {
	struct watchList *next;
	int wd;
	char *dir;
	struct stringsList *files;
};
struct watchList *firstDir = NULL;

/* Compare two contexts to see if their differences are "significant",
 * or whether the only difference is in the user. */
static int only_changed_user(const char *a, const char *b)
{
	char *rest_a, *rest_b;	/* Rest of the context after the user */
	if (!a || !b)
		return 0;
	rest_a = strchr(a, ':');
	rest_b = strchr(b, ':');
	if (!rest_a || !rest_b)
		return 0;
	return (strcmp(rest_a, rest_b) == 0);
}

/* 
   A file was in a direcroty has been created. This function checks to 
   see if it is one that we are watching.
*/

static int watch_list_find(int wd, const char *file)
{
	struct watchList *ptr = NULL;
	ptr = firstDir;

	if (debug_mode)
		printf("%d: File=%s\n", wd, file);
	while (ptr != NULL) {
		if (ptr->wd == wd) {
			int exact=0;
			if (strings_list_find(ptr->files, file, &exact) == 0) {
				char *path = NULL;
				if (asprintf(&path, "%s/%s", ptr->dir, file) <
				    0)
					exitApp("Error allocating memory.");
				restore(path, exact);
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

static void watch_list_free(int fd)
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
   Set the file context to the default file context for this system.
   Same as restorecon.
*/
static void restore(const char *filename, int exact)
{
	int retcontext = 0;
	security_context_t scontext = NULL;
	security_context_t prev_context = NULL;
	struct stat st;
	int fd = -1;
	if (debug_mode)
		printf("restore %s\n", filename);

	fd = open(filename, O_NOFOLLOW | O_RDONLY);
	if (fd < 0) {
		if (verbose_mode)
			syslog(LOG_ERR, "Unable to open file (%s) %s\n",
			       filename, strerror(errno));
		return;
	}

	if (fstat(fd, &st) != 0) {
		syslog(LOG_ERR, "Unable to stat file (%s) %s\n", filename,
		       strerror(errno));
		close(fd);
		return;
	}

	if (!(st.st_mode & S_IFDIR) && st.st_nlink > 1) {
		if (exact) { 
			syslog(LOG_ERR,
			       "Will not restore a file with more than one hard link (%s) %s\n",
			       filename, strerror(errno));
		}
		close(fd);
		return;
	}

	if (matchpathcon(filename, st.st_mode, &scontext) < 0) {
		if (errno == ENOENT)
			return;
		syslog(LOG_ERR, "matchpathcon(%s) failed %s\n", filename,
		       strerror(errno));
		return;
	}
	retcontext = fgetfilecon_raw(fd, &prev_context);

	if (retcontext >= 0 || errno == ENODATA) {
		if (retcontext < 0)
			prev_context = NULL;
		if (retcontext < 0 || (strcmp(prev_context, scontext) != 0)) {

			if (only_changed_user(scontext, prev_context) != 0) {
				free(scontext);
				free(prev_context);
				close(fd);
				return;
			}

			if (fsetfilecon(fd, scontext) < 0) {
				if (errno != EOPNOTSUPP) 
					syslog(LOG_ERR,
					       "set context %s->%s failed:'%s'\n",
					       filename, scontext, strerror(errno));
				if (retcontext >= 0)
					free(prev_context);
				free(scontext);
				close(fd);
				return;
			}
			syslog(LOG_WARNING, "Reset file context %s: %s->%s\n",
			       filename, prev_context, scontext);
		}
		if (retcontext >= 0)
			free(prev_context);
	} else {
		if (errno != EOPNOTSUPP) 
			syslog(LOG_ERR, "get context on %s failed: '%s'\n",
			       filename, strerror(errno));
	}
	free(scontext);
	close(fd);
}

static void process_config(int fd, FILE * cfg)
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
		if (buffer[0] == '~')
			utmpwatcher_add(fd, &buffer[1]);
		else {
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

static void read_config(int fd)
{
	char *watch_file_path = "/etc/selinux/restorecond.conf";

	FILE *cfg = NULL;
	if (debug_mode)
		printf("Read Config\n");

	watch_list_free(fd);

	cfg = fopen(watch_file_path, "r");
	if (!cfg)
		exitApp("Error reading config file.");
	process_config(fd, cfg);
	fclose(cfg);

	inotify_rm_watch(fd, master_wd);
	master_wd =
	    inotify_add_watch(fd, watch_file_path, IN_MOVED_FROM | IN_MODIFY);
	if (master_wd == -1)
		exitApp("Error watching config file.");
}

/* 
   Inotify watch loop 
*/
static int watch(int fd)
{
	char buf[BUF_LEN];
	int len, i = 0;
	len = read(fd, buf, BUF_LEN);
	if (len < 0) {
		if (terminate == 0) {
			syslog(LOG_ERR, "Read error (%s)", strerror(errno));
			return 0;
		}
		syslog(LOG_ERR, "terminated");
		return -1;
	} else if (!len)
		/* BUF_LEN too small? */
		return -1;
	while (i < len) {
		struct inotify_event *event;
		event = (struct inotify_event *)&buf[i];
		if (debug_mode)
			printf("wd=%d mask=%u cookie=%u len=%u\n",
			       event->wd, event->mask,
			       event->cookie, event->len);

		if (event->mask & ~IN_IGNORED) {
			if (event->wd == master_wd)
				read_config(fd);
			else {
				switch (utmpwatcher_handle(fd, event->wd)) {
				case -1:	/* Message was not for utmpwatcher */
					if (event->len)
						watch_list_find(event->wd, event->name);
					break;

				case 1:	/* utmp has changed need to reload */
					read_config(fd);
					break;

				default:	/* No users logged in or out */
					break;
				}
			}
		}

		i += EVENT_SIZE + event->len;
	}
	return 0;
}

static const char *pidfile = "/var/run/restorecond.pid";

static int write_pid_file(void)
{
	int pidfd, len;
	char val[16];

	len = snprintf(val, sizeof(val), "%u\n", getpid());
	if (len < 0) {
		syslog(LOG_ERR, "Pid error (%s)", strerror(errno));
		pidfile = 0;
		return 1;
	}
	pidfd = open(pidfile, O_CREAT | O_TRUNC | O_NOFOLLOW | O_WRONLY, 0644);
	if (pidfd < 0) {
		syslog(LOG_ERR, "Unable to set pidfile (%s)", strerror(errno));
		pidfile = 0;
		return 1;
	}
	(void)write(pidfd, val, (unsigned int)len);
	close(pidfd);
	return 0;
}

/*
 * SIGTERM handler
 */
static void term_handler()
{
	terminate = 1;
	/* trigger a failure in the watch */
	close(master_fd);
}

static void usage(char *program)
{
	printf("%s [-d] [-v] \n", program);
	exit(0);
}

void exitApp(const char *msg)
{
	perror(msg);
	exit(-1);
}

/* 
   Add a file to the watch list.  We are watching for file creation, so we actually
   put the watch on the directory and then examine all files created in that directory
   to see if it is one that we are watching.
*/

void watch_list_add(int fd, const char *path)
{
	struct watchList *ptr = NULL;
	struct watchList *prev = NULL;
	char *x = strdup(path);
	if (!x)
		exitApp("Out of Memory");
	char *dir = dirname(x);
	char *file = basename(path);
	ptr = firstDir;

	restore(path, 1);

	while (ptr != NULL) {
		if (strcmp(dir, ptr->dir) == 0) {
			strings_list_add(&ptr->files, file);
			free(x);
			return;
		}
		prev = ptr;
		ptr = ptr->next;
	}
	ptr = calloc(1, sizeof(struct watchList));

	if (!ptr)
		exitApp("Out of Memory");

	ptr->wd = inotify_add_watch(fd, dir, IN_CREATE | IN_MOVED_TO);
	if (ptr->wd == -1) {
		free(ptr);
		syslog(LOG_ERR, "Unable to watch (%s) %s\n",
		       path, strerror(errno));
		return;
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

	free(x);
}

int main(int argc, char **argv)
{
	int opt;
	struct sigaction sa;

#ifndef DEBUG
	/* Make sure we are root */
	if (getuid() != 0) {
		fprintf(stderr, "You must be root to run this program.\n");
		return 1;
	}
#endif
	/* Make sure we are root */
	if (is_selinux_enabled() != 1) {
		fprintf(stderr, "Daemon requires SELinux be enabled to run.\n");
		return 1;
	}

	/* Register sighandlers */
	sa.sa_flags = 0;
	sa.sa_handler = term_handler;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGTERM, &sa, NULL);

	set_matchpathcon_flags(MATCHPATHCON_NOTRANS);

	master_fd = inotify_init();
	if (master_fd < 0)
		exitApp("inotify_init");

	while ((opt = getopt(argc, argv, "dv")) > 0) {
		switch (opt) {
		case 'd':
			debug_mode = 1;
			break;
		case 'v':
			verbose_mode = 1;
			break;
		case '?':
			usage(argv[0]);
		}
	}
	read_config(master_fd);

	if (!debug_mode)
		daemon(0, 0);

	write_pid_file();

	while (watch(master_fd) == 0) {
	};

	watch_list_free(master_fd);
	close(master_fd);
	matchpathcon_fini();
	utmpwatcher_free();
	if (pidfile)
		unlink(pidfile);

	return 0;
}
