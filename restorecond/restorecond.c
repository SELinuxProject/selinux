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
 * restorecond [-d] [-u] [-v] [-f restorecond_file ]
 * 
 * -d   Run in debug mode
 * -f   Use alternative restorecond_file
 * -u   Run in user mode
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
#include "restore.h"
#include <sys/types.h>
#include <syslog.h>
#include <limits.h>
#include <pwd.h>
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include "restorecond.h"
#include "utmpwatcher.h"

const char *homedir;
static int master_fd = -1;

static const char *server_watch_file  = "/etc/selinux/restorecond.conf";
static const char *user_watch_file  = "/etc/selinux/restorecond_user.conf";
static const char *watch_file;
struct restore_opts r_opts;

#include <selinux/selinux.h>

int debug_mode = 0;
int terminate = 0;
int master_wd = -1;
int run_as_user = 0;

static void done(void) {
	watch_list_free(master_fd);
	close(master_fd);
	utmpwatcher_free();
	selabel_close(r_opts.hnd);
}

static const char *pidfile = "/run/restorecond.pid";

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
	if (write(pidfd, val, (unsigned int)len) != len) {
		syslog(LOG_ERR, "Unable to write to pidfile (%s)", strerror(errno));
		close(pidfd);
		return 1;
	}
	close(pidfd);
	return 0;
}

/*
 * SIGTERM handler
 */
static void term_handler(int s __attribute__ ((unused)))
{
	terminate = 1;
	/* trigger a failure in the watch */
	close(master_fd);
}

static void usage(char *program)
{
	printf("%s [-d] [-f restorecond_file ] [-u] [-v] \n", program);
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

int main(int argc, char **argv)
{
	int opt;
	struct sigaction sa;

	/* If we are not running SELinux then just exit */
	if (is_selinux_enabled() != 1)
		return 0;

	watch_file = server_watch_file;

	/* Set all options to zero/NULL except for ignore_noent & digest. */
	memset(&r_opts, 0, sizeof(r_opts));
	r_opts.ignore_noent = SELINUX_RESTORECON_IGNORE_NOENTRY;
	r_opts.ignore_digest = SELINUX_RESTORECON_IGNORE_DIGEST;

	/* As r_opts.selabel_opt_digest = NULL, no digest will be requested. */
	restore_init(&r_opts);

	/* Register sighandlers */
	sa.sa_flags = 0;
	sa.sa_handler = term_handler;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGTERM, &sa, NULL);

	atexit( done );
	while ((opt = getopt(argc, argv, "hdf:uv")) > 0) {
		switch (opt) {
		case 'd':
			debug_mode = 1;
			break;
		case 'f':
			watch_file = optarg;
			break;
		case 'u':
			run_as_user = 1;
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
			break;
		case 'v':
			r_opts.verbose = SELINUX_RESTORECON_VERBOSE;
			break;
		case '?':
			usage(argv[0]);
			exit(-1);
		}
	}

	master_fd = inotify_init();
	if (master_fd < 0)
		exitApp("inotify_init");

	uid_t uid = getuid();
	struct passwd *pwd = getpwuid(uid);
	if (!pwd)
		exitApp("getpwuid");

	homedir = pwd->pw_dir;
	if (uid != 0) {
		if (run_as_user)
			return server(master_fd, user_watch_file);
		if (start() != 0)
			return server(master_fd, user_watch_file);
		return 0;
	}

	read_config(master_fd, watch_file);

	if (!debug_mode) {
		if (daemon(0, 0) < 0)
			exitApp("daemon");
	}

	write_pid_file();

	while (watch(master_fd, watch_file) == 0) {
	}

	watch_list_free(master_fd);
	close(master_fd);

	if (pidfile)
		unlink(pidfile);

	return 0;
}
