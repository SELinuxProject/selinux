/* restorecond.h -- 
 * Copyright 2006 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *   Dan Walsh <dwalsh@redhat.com>
 * 
 */

#ifndef RESTORED_CONFIG_H
#define RESTORED_CONFIG_H

extern int debug_mode;
extern const char *homedir;
extern int terminate;
extern int master_wd;
extern int run_as_user;

extern int start(void);
extern int server(int, const char *watch_file);

extern void exitApp(const char *msg) __attribute__((__noreturn__));
extern void read_config(int fd,	const char *watch_file);

extern int watch(int fd, const char *watch_file);
extern void watch_list_add(int inotify_fd, const char *path);
extern int watch_list_find(int wd, const char *file);
extern void watch_list_free(int fd);
extern int watch_list_isempty(void);

extern struct restore_opts r_opts;

#endif
