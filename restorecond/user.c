/*
 * restorecond
 *
 * Copyright (C) 2006-2009 Red Hat
 * Copyright (C) 2020 Nicolas Iooss
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
 *   Nicolas Iooss <nicolas.iooss@m4x.org>
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
#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <limits.h>
#include <fcntl.h>

#include <selinux/selinux.h>

#include "restorecond.h"
#include "stringslist.h"
#include <glib.h>
#include <glib-unix.h>

static int local_lock_fd = -1;

#ifdef HAVE_DBUS
#include <gio/gio.h>

static const char *DBUS_NAME = "org.selinux.Restorecond";

static void on_name_acquired(GDBusConnection *connection G_GNUC_UNUSED,
			     const gchar *name,
			     gpointer user_data G_GNUC_UNUSED)
{
	if (debug_mode)
		g_print("D-Bus name acquired: %s\n", name);
}

static void on_name_lost(GDBusConnection *connection G_GNUC_UNUSED,
			 const gchar *name,
			 gpointer user_data)
{
	/* Exit when the D-Bus connection closes */
	GMainLoop *loop = user_data;

	if (debug_mode)
		g_print("D-Bus name lost (%s), exiting\n", name);
	g_main_loop_quit(loop);
}

/**
 * Try starting a D-Bus server on the session bus.
 * Returns -1 if the connection failed, so that a local server can be launched
 */
static int dbus_server(GMainLoop *loop)
{
	GDBusConnection *bus;
	guint client_id;

	bus = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, NULL);
	if (!bus)
		return -1;

	client_id = g_bus_own_name_on_connection(
		bus,
		DBUS_NAME,
		G_BUS_NAME_OWNER_FLAGS_NONE,
		on_name_acquired,
		on_name_lost,
		loop,
		NULL);
	g_object_unref(bus);
	if (client_id == 0)
		return -1;

	return 0;
}

#endif

/* size of the event structure, not counting name */
#define EVENT_SIZE  (sizeof (struct inotify_event))
/* reasonable guess as to size of 1024 events */
#define BUF_LEN        (1024 * (EVENT_SIZE + 16))

static gboolean
io_channel_callback
 (GIOChannel *source,
  GIOCondition condition,
  gpointer data __attribute__((__unused__)))
{

  char buffer[BUF_LEN+1];
  gsize bytes_read;
  unsigned int i = 0;

  if (condition & G_IO_IN) {
    /* Data is available. */
    g_io_channel_read_chars
      (source, buffer,
       sizeof (buffer),
       &bytes_read, NULL);

    if (! bytes_read) {
	    /* Session/Terminal Ended */
	    exit(0);
    }

    while (i < bytes_read) {
	    struct inotify_event *event;
	    event = (struct inotify_event *)&buffer[i];
	    if (debug_mode)
		    printf("wd=%d mask=%u cookie=%u len=%u\n",
			   event->wd, event->mask,
			   event->cookie, event->len);
	    if (event->len)
		    watch_list_find(event->wd, event->name);

	    i += EVENT_SIZE + event->len;
    }
  }

  /* An error happened while reading
     the file. */

  if (condition & G_IO_NVAL)
    return FALSE;

  /* We have reached the end of the
     file. */

  if (condition & G_IO_HUP) {
    g_io_channel_shutdown (source, 0, NULL);
    exit(0);
    return FALSE;
  }

  /* Returning TRUE will make sure
     the callback remains associated
     to the channel. */

  return TRUE;
}

int start() {
#ifdef HAVE_DBUS
	GDBusConnection *bus;
	GError *err = NULL;
	GVariant *result;

	/* Get a connection to the session bus */
	bus = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &err);
	if (!bus) {
		if (debug_mode)
			g_warning("Failed to connect to the D-BUS daemon: %s", err->message);
		g_error_free(err);
		return 1;
	}

	/* Start restorecond D-Bus service by pinging its bus name
	 *
	 * https://dbus.freedesktop.org/doc/dbus-specification.html#standard-interfaces-peer
	 */
	result = g_dbus_connection_call_sync(bus,
					     DBUS_NAME, /* bus name */
					     "/", /* object path */
					     "org.freedesktop.DBus.Peer", /* interface */
					     "Ping", /* method */
					     NULL, /* parameters */
					     NULL, /* reply_type */
					     G_DBUS_CALL_FLAGS_NONE,
					     -1, /* timeout_msec */
					     NULL,
					     &err);
	if (!result) {
		g_object_unref(bus);
		if (debug_mode)
			g_warning("Failed to start %s: %s", DBUS_NAME, err->message);
		g_error_free(err);
		return 1;
	}
	g_object_unref(bus);
#endif /* HAVE_DBUS */
	return 0;
}

static int local_server(void) {
	// ! dbus, run as local service
	char *ptr=NULL;
	if (asprintf(&ptr, "%s/.restorecond", homedir) < 0) {
		if (debug_mode)
			perror("asprintf");
		return -1;
	}
	local_lock_fd = open(ptr, O_CREAT | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, S_IRUSR | S_IWUSR);
	if (debug_mode)
		g_warning ("Lock file: %s", ptr);

	free(ptr);
	if (local_lock_fd < 0) {
		if (debug_mode)
			perror("open");
		return -1;
	}
	if (flock(local_lock_fd, LOCK_EX | LOCK_NB) < 0) {
		close(local_lock_fd);
		if (debug_mode)
			perror("flock");
		return -1;
	}
	/* watch for stdin/terminal going away */
	GIOChannel *in = g_io_channel_unix_new(0);
	g_io_add_watch_full( in,
			     G_PRIORITY_HIGH,
			     G_IO_IN|G_IO_ERR|G_IO_HUP,
			     io_channel_callback, NULL, NULL);

	return 0;
}

static void end_local_server(void) {
	if (local_lock_fd >= 0)
		close(local_lock_fd);
	local_lock_fd = -1;
}

static int sigterm_handler(gpointer user_data)
{
	GMainLoop *loop = user_data;

	if (debug_mode)
		g_print("Received SIGTERM, exiting\n");
	g_main_loop_quit(loop);
	return FALSE;
}


int server(int master_fd, const char *watch_file) {
	GMainLoop *loop;

	loop = g_main_loop_new (NULL, FALSE);

#ifdef HAVE_DBUS
	if (dbus_server(loop) != 0)
#endif /* HAVE_DBUS */
		if (local_server())
			goto end;

	read_config(master_fd, watch_file);

	if (watch_list_isempty())
		goto end;

	set_matchpathcon_flags(MATCHPATHCON_NOTRANS);

	GIOChannel *c = g_io_channel_unix_new(master_fd);

	g_io_add_watch_full(c,
			    G_PRIORITY_HIGH,
			    G_IO_IN|G_IO_ERR|G_IO_HUP,
			    io_channel_callback, NULL, NULL);

	/* Handle SIGTERM */
	g_unix_signal_add_full(G_PRIORITY_DEFAULT,
			       SIGTERM,
			       sigterm_handler,
			       loop,
			       NULL);

	g_main_loop_run (loop);

end:
	end_local_server();
	g_main_loop_unref (loop);
	return 0;
}

