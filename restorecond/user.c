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
#include <glib.h>
#ifdef HAVE_DBUS
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>

static DBusHandlerResult signal_filter (DBusConnection *connection, DBusMessage *message, void *user_data);

static const char *PATH="/org/selinux/Restorecond";
//static const char *BUSNAME="org.selinux.Restorecond";
static const char *INTERFACE="org.selinux.RestorecondIface";
static const char *RULE="type='signal',interface='org.selinux.RestorecondIface'";

static int local_lock_fd = -1;

static DBusHandlerResult
signal_filter (DBusConnection *connection  __attribute__ ((__unused__)), DBusMessage *message, void *user_data)
{
  /* User data is the event loop we are running in */
  GMainLoop *loop = user_data;

  /* A signal from the bus saying we are about to be disconnected */
  if (dbus_message_is_signal
        (message, INTERFACE, "Stop")) {

      /* Tell the main loop to quit */
      g_main_loop_quit (loop);
      /* We have handled this message, don't pass it on */
      return DBUS_HANDLER_RESULT_HANDLED;
  }
  /* A Ping signal on the com.burtonini.dbus.Signal interface */
  else if (dbus_message_is_signal (message, INTERFACE, "Start")) {
    DBusError error;
    dbus_error_init (&error);
    g_print("Start received\n");
    return DBUS_HANDLER_RESULT_HANDLED;
  }
  return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static int dbus_server(GMainLoop *loop) {
    DBusConnection *bus;
    DBusError error;
    dbus_error_init (&error);
    bus = dbus_bus_get (DBUS_BUS_SESSION, &error);
    if (bus) {
	dbus_connection_setup_with_g_main (bus, NULL);

	/* listening to messages from all objects as no path is specified */
	dbus_bus_add_match (bus, RULE, &error); // see signals from the given interfacey
	dbus_connection_add_filter (bus, signal_filter, loop, NULL);
	return 0;
    }
    return -1;
}

#endif
#include <selinux/selinux.h>
#include <sys/file.h>

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
	    /* Sesssion/Terminal Ended */
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
	DBusConnection *bus;
	DBusError error;
	DBusMessage *message;

	/* Get a connection to the session bus */
	dbus_error_init (&error);
	bus = dbus_bus_get (DBUS_BUS_SESSION, &error);
	if (!bus) {
		if (debug_mode)
			g_warning ("Failed to connect to the D-BUS daemon: %s", error.message);
		dbus_error_free (&error);
		return 1;
	}


	/* Create a new signal "Start" on the interface,
	 * from the object  */
	message = dbus_message_new_signal (PATH,
					   INTERFACE, "Start");
	/* Send the signal */
	dbus_connection_send (bus, message, NULL);
	/* Free the signal now we have finished with it */
	dbus_message_unref (message);
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

int server(int master_fd, const char *watch_file) {
    GMainLoop *loop;

    loop = g_main_loop_new (NULL, FALSE);

#ifdef HAVE_DBUS
    if (dbus_server(loop) != 0)
#endif /* HAVE_DBUS */
	    if (local_server())
		    goto end;

    read_config(master_fd, watch_file);

    if (watch_list_isempty()) goto end;

    set_matchpathcon_flags(MATCHPATHCON_NOTRANS);

    GIOChannel *c = g_io_channel_unix_new(master_fd);

    g_io_add_watch_full( c,
			 G_PRIORITY_HIGH,
			 G_IO_IN|G_IO_ERR|G_IO_HUP,
			 io_channel_callback, NULL, NULL);

    g_main_loop_run (loop);

end:
    end_local_server();
    g_main_loop_unref (loop);
    return 0;
}

