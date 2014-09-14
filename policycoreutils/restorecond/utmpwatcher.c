/*
 * utmpwatcher.c
 *
 * Copyright (C) 2006 Red Hat 
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
 *
*/

#define _GNU_SOURCE
#include <sys/inotify.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>

#include <limits.h>
#include <utmp.h>
#include <sys/types.h>
#include <pwd.h>
#include "restorecond.h"
#include "utmpwatcher.h"
#include "stringslist.h"

static struct stringsList *utmp_ptr = NULL;
static int utmp_wd = -1;

unsigned int utmpwatcher_handle(int inotify_fd, int wd)
{
	int changed = 0;
	struct utmp u;
	const char *utmp_path = "/var/run/utmp";
	struct stringsList *prev_utmp_ptr = utmp_ptr;
	if (wd != utmp_wd)
		return -1;

	utmp_ptr = NULL;
	FILE *cfg = fopen(utmp_path, "r");
	if (!cfg)
		exitApp("Error reading utmp file.");

	while (fread(&u, sizeof(struct utmp), 1, cfg) > 0) {
		if (u.ut_type == USER_PROCESS)
			strings_list_add(&utmp_ptr, u.ut_user);
	}
	fclose(cfg);
	if (utmp_wd >= 0)
		inotify_rm_watch(inotify_fd, utmp_wd);

	utmp_wd =
	    inotify_add_watch(inotify_fd, utmp_path, IN_MOVED_FROM | IN_MODIFY);
	if (utmp_wd == -1)
		exitApp("Error watching utmp file.");

	changed = strings_list_diff(prev_utmp_ptr, utmp_ptr);
	if (prev_utmp_ptr) {
		strings_list_free(prev_utmp_ptr);
	}
	return changed;
}

static void watch_file(int inotify_fd, const char *file)
{
	struct stringsList *ptr = utmp_ptr;

	while (ptr) {
		struct passwd *pwd = getpwnam(ptr->string);
		if (pwd) {
			char *path = NULL;
			if (asprintf(&path, "%s%s", pwd->pw_dir, file) < 0)
				exitApp("Error allocating memory.");
			watch_list_add(inotify_fd, path);
			free(path);
		}
		ptr = ptr->next;
	}
}

void utmpwatcher_add(int inotify_fd, const char *path)
{
	if (utmp_ptr == NULL) {
		utmpwatcher_handle(inotify_fd, utmp_wd);
	}
	watch_file(inotify_fd, path);
}

void utmpwatcher_free(void)
{
	if (utmp_ptr)
		strings_list_free(utmp_ptr);
}

#ifdef TEST
int main(int argc, char **argv)
{
	read_utmp();
	return 0;
}
#endif
