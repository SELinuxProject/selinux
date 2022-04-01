/* Copyright (c) 2006 Trusted Computer Solutions, Inc. */
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <selinux/selinux.h>
#include <sys/capability.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>

#include "mcscolor.h"
#include "mcstrans.h"

#ifdef UNUSED
#elif defined(__GNUC__)
# define UNUSED(x) UNUSED_ ## x __attribute__((unused))
#elif defined(__LCLINT__)
# define UNUSED(x) /*@unused@*/ x
#else
# define UNUSED(x) x
#endif

#define SETRANS_UNIX_SOCKET "/var/run/setrans/.setrans-unix"

#define SETRANS_INIT			1
#define RAW_TO_TRANS_CONTEXT		2
#define TRANS_TO_RAW_CONTEXT		3
#define RAW_CONTEXT_TO_COLOR		4
#define MAX_DATA_BUF			4096
#define MAX_DESCRIPTORS			8192

#ifdef DEBUG
//#define log_debug(fmt, ...) syslog(LOG_DEBUG, fmt, __VA_ARGS__)
#define log_debug(fmt, ...) fprintf(stderr, fmt, __VA_ARGS__)
#else
#define log_debug(fmt, ...) do {} while (0)
#endif

#define SETRANSD_PATHNAME "/sbin/mcstransd"

/* name of program (for error messages) */
#define SETRANSD_PROGNAME "mcstransd"

static int sockfd = -1;	/* socket we are listening on */

static volatile int restart_daemon = 0;
static void cleanup_exit(int ret) __attribute__ ((noreturn));
static void
cleanup_exit(int ret) 
{
	finish_context_colors();
	finish_context_translations();
	if (sockfd >=0)
		(void)unlink(SETRANS_UNIX_SOCKET);

	log_debug("%s\n", "cleanup_exit");

	exit(ret);
}

static void clean_exit(void);
static  __attribute__((noreturn)) void clean_exit(void)
{
	log_debug("%s\n", "clean_exit");
	cleanup_exit(0);
}

static int
send_response(int fd, uint32_t function, char *data, int32_t ret_val)
{
	struct iovec resp_hdr[3];
	uint32_t data_size;
	struct iovec resp_data;
	ssize_t count;

	if (!data)
		data = (char *)"";

	data_size = strlen(data) + 1;

	resp_hdr[0].iov_base = &function;
	resp_hdr[0].iov_len = sizeof(function);
	resp_hdr[1].iov_base = &data_size;
	resp_hdr[1].iov_len = sizeof(data_size);
	resp_hdr[2].iov_base = &ret_val;
	resp_hdr[2].iov_len = sizeof(ret_val);

	while (((count = writev(fd, resp_hdr, 3)) < 0) && (errno == EINTR));
	if (count != (sizeof(function) + sizeof(data_size) + sizeof(ret_val))) {
		syslog(LOG_ERR, "Failed to write response header");
		return -1;
	}

	resp_data.iov_base = data;
	resp_data.iov_len = data_size;

	while (((count = writev(fd, &resp_data, 1)) < 0) && (errno == EINTR));
	if (count < 0 || (size_t)count != data_size) {
		syslog(LOG_ERR, "Failed to write response data");
		return -1;
	}

	return ret_val;
}

static int
get_peer_pid(int fd, pid_t *pid)
{
	int ret;
	socklen_t size = sizeof(struct ucred);
	struct ucred peercred;

	/* get the context of the requesting process */
	ret = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peercred, &size);
	if (ret < 0) {
		syslog(LOG_ERR, "Failed to get PID of client process");
		return -1;
	}
	*pid = peercred.pid;
	return ret;
}


static int
process_request(int fd, uint32_t function, char *data1, char *UNUSED(data2))
{
	int32_t result;
	char *out = NULL;
	int ret;

	switch (function) {
	case SETRANS_INIT:
		result = 0;
		ret = send_response(fd, function, NULL, result);
		break;
	case RAW_TO_TRANS_CONTEXT:
		result = trans_context(data1, &out);
		ret = send_response(fd, function, out, result);
		break;
	case TRANS_TO_RAW_CONTEXT:
		result = untrans_context(data1, &out);
		ret = send_response(fd, function, out, result);
		break;
	case RAW_CONTEXT_TO_COLOR:
		result = raw_color(data1, &out);
		ret = send_response(fd, function, out, result);
		break;
	default:
		result = -1;
		ret = -1;
		break;
	}

	if (result) {
		pid_t pid = 0;
		get_peer_pid(fd, &pid);
		syslog(LOG_ERR, "Invalid request func=%d from=%u",
		       function, pid);
	}

	free(out);

	return ret;
}

static int
service_request(int fd)
{
	struct iovec req_hdr[3];
	uint32_t function;
	uint32_t data1_size;
	uint32_t data2_size;
	struct iovec req_data[2];
	char *data1;
	char *data2;
	int ret;
	ssize_t count;

	req_hdr[0].iov_base = &function;
	req_hdr[0].iov_len = sizeof(function);
	req_hdr[1].iov_base = &data1_size;
	req_hdr[1].iov_len = sizeof(data1_size);
	req_hdr[2].iov_base = &data2_size;
	req_hdr[2].iov_len = sizeof(data2_size);

	while (((count = readv(fd, req_hdr, 3)) < 0) && (errno == EINTR));
	if (count <= 0) {
		return 1;
	}
	if (count != (sizeof(function) + sizeof(data1_size) +
	              sizeof(data2_size) )) {
		log_debug("Failed to read request header %d != %u\n",(int)count,
			(unsigned)(sizeof(function) + sizeof(data1_size) +
                      sizeof(data2_size) ));
		return -1;
	}

	if (!data1_size || !data2_size || data1_size > MAX_DATA_BUF ||
						data2_size > MAX_DATA_BUF ) {
		log_debug("Header invalid data1_size=%u data2_size=%u\n",
		        data1_size, data2_size);
		return -1;
	}

	data1 = malloc(data1_size);
	if (!data1) {
		log_debug("Could not allocate %d bytes\n", data1_size);
		return -1; 
	}
	data2 = malloc(data2_size);
	if (!data2) {
		free(data1);
		log_debug("Could not allocate %d bytes\n", data2_size);
		return -1;
	}

	req_data[0].iov_base = data1;
	req_data[0].iov_len = data1_size;
	req_data[1].iov_base = data2;
	req_data[1].iov_len = data2_size;

	while (((count = readv(fd, req_data, 2)) < 0) && (errno == EINTR));
	if (count <= 0 || (size_t)count != (data1_size + data2_size) ||
	    data1[data1_size - 1] != '\0' || data2[data2_size - 1] != '\0') {
		free(data1);
		free(data2);
		log_debug("Failed to read request data (%d)\n", (int)count);
		return -1;
	}

	ret = process_request(fd, function, data1, data2);

	free(data1);
	free(data2);

	return ret;
}

static int
add_pollfd(struct pollfd **ufds, int *nfds, int connfd)
{
	int ii = 0;

	/* First see if we can find an already invalidated ufd */
	for (ii = 0; ii < *nfds; ii++) {
		if ((*ufds)[ii].fd == -1)
			break;
	}

	if (ii == *nfds) {
		struct pollfd *tmp = (struct pollfd *)realloc(*ufds,
					(*nfds+1)*sizeof(struct pollfd));
		if (!tmp) {
			syslog(LOG_ERR, "realloc failed for %d fds", *nfds+1);
			return -1;
		}

		*ufds = tmp;
		(*nfds)++;
	}

	(*ufds)[ii].fd = connfd;
	(*ufds)[ii].events = POLLIN|POLLPRI;
	(*ufds)[ii].revents = 0;

	return 0;
}

static void
adj_pollfds(struct pollfd **ufds, int *nfds)
{
	int ii, jj;

	jj = 0;
	for (ii = 0; ii < *nfds; ii++) {
		if ((*ufds)[ii].fd != -1) {
			if (jj < ii)
				(*ufds)[jj] = (*ufds)[ii];
			jj++;
		}
	}
	*nfds = jj;
}

static int
process_events(struct pollfd **ufds, int *nfds)
{
	int ii = 0;
	int ret = 0;

	for (ii = 0; ii < *nfds; ii++) {
		short revents = (*ufds)[ii].revents;
		int connfd = (*ufds)[ii].fd;

		if (revents & (POLLIN | POLLPRI)) {
			if (connfd == sockfd) {

				/* Probably received a connection */
				if ((connfd = accept(sockfd, NULL, NULL)) < 0) {
					syslog(LOG_ERR, "accept() failed: %m");
					return -1;
				}

				if (add_pollfd(ufds, nfds, connfd)) {
					syslog(LOG_ERR,
					  "Failed to add fd (%d) to poll list\n",
						connfd);
					return -1;
				}
			} else {
				ret = service_request(connfd);
				if (ret) {
					if (ret < 0) {
						syslog(LOG_ERR,
							"Servicing of request "
							"failed for fd (%d)\n",
							connfd);
					}
					/* Setup pollfd for deletion later. */
					(*ufds)[ii].fd = -1;
					close(connfd);
					connfd = -1;
					/* So we don't get bothered later */
					revents = revents & ~(POLLHUP);
				}
			}
			revents = revents & ~(POLLIN | POLLPRI);
		}
		if (revents & POLLHUP) {
			log_debug("The connection with fd (%d) hung up\n",
				connfd);

			/* Set the pollfd up for deletion later. */
			(*ufds)[ii].fd = -1;
			close(connfd);
			connfd = -1;

			revents = revents & ~(POLLHUP);
		}
		if (revents && connfd != -1) {
			syslog(LOG_ERR, "Unknown/error events (%x) encountered"
					" for fd (%d)\n", revents, connfd);

			/* Set the pollfd up for deletion later. */
			(*ufds)[ii].fd = -1;
			close(connfd);
		}

		(*ufds)[ii].revents = 0;
	}

	/* Delete any invalidated ufds */
	adj_pollfds(ufds, nfds);

	return 0;
}

static void
process_connections(void) __attribute__ ((noreturn));

static void
process_connections(void)
{
	int ret = 0;
	int nfds = 1;

	struct pollfd *ufds = (struct pollfd *)malloc(sizeof(struct pollfd));
	if (!ufds) {
		syslog(LOG_ERR, "Failed to allocate a pollfd");
		cleanup_exit(1);
	}
	ufds[0].fd = sockfd;
	ufds[0].events = POLLIN|POLLPRI;
	ufds[0].revents = 0;

	while (1) {
		if (restart_daemon) {
			syslog(LOG_NOTICE, "Reload Translations");
			finish_context_colors();
			finish_context_translations();
			if (init_translations()) {
				syslog(LOG_ERR, "Failed to initialize label translations");
				cleanup_exit(1);
			}
			if (init_colors()) {
				syslog(LOG_ERR, "Failed to initialize color translations");
				syslog(LOG_ERR, "No color information will be available");
			}
			restart_daemon = 0;
		}

		ret = poll(ufds, nfds, -1);
		if (ret < 0) {
			if (errno == EINTR) {
				continue;
			}
			syslog(LOG_ERR, "poll() failed: %m");
			cleanup_exit(1);
		}

		ret = process_events(&ufds, &nfds);
		if (ret) {
			syslog(LOG_ERR, "Error processing events");
			cleanup_exit(1);
		}
	}
}

static void
sigterm_handler(int sig) __attribute__ ((noreturn));

static void
sigterm_handler(int UNUSED(sig))
{
	cleanup_exit(0);
}

static void
sighup_handler(int UNUSED(sig))
{
	restart_daemon = 1;
}

static void
initialize(void)
{
	struct sigaction act;
	struct sockaddr_un addr;
	struct rlimit rl ;

	if (init_translations()) {
		syslog(LOG_ERR, "Failed to initialize label translations");
		cleanup_exit(1);
	}
	if (init_colors()) {
		syslog(LOG_ERR, "Failed to initialize color translations");
		syslog(LOG_ERR, "No color information will be available");
	}

	/* the socket will be unlinked when the daemon terminates */
	act.sa_handler = sigterm_handler;
	sigemptyset(&act.sa_mask);
	sigaddset(&act.sa_mask, SIGINT);
	sigaddset(&act.sa_mask, SIGQUIT);
	sigaddset(&act.sa_mask, SIGTERM);
	sigaddset(&act.sa_mask, SIGHUP);
	act.sa_flags = 0;
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGQUIT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);

	/* restart the daemon on SIGHUP */
	act.sa_handler = sighup_handler;
	sigemptyset(&act.sa_mask);
	sigaddset(&act.sa_mask, SIGINT);
	sigaddset(&act.sa_mask, SIGQUIT);
	sigaddset(&act.sa_mask, SIGTERM);
	act.sa_flags = 0;
	sigaction(SIGHUP, &act, NULL);

	/* ignore SIGPIPE (in case a client terminates after sending request) */
	act.sa_handler = SIG_IGN;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SIGPIPE, &act, NULL);

	atexit(clean_exit);

	sockfd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sockfd < 0)	{
		syslog(LOG_ERR, "socket() failed: %m");
		cleanup_exit(1);
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, SETRANS_UNIX_SOCKET, sizeof(addr.sun_path) - 1);

	(void)unlink(SETRANS_UNIX_SOCKET);

	if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		syslog(LOG_ERR, "bind() failed: %m");
		cleanup_exit(1);
	}

	if (listen(sockfd, SOMAXCONN) < 0) {
		syslog(LOG_ERR, "listen() failed: %m");
		cleanup_exit(1);
	}

	if (chmod(SETRANS_UNIX_SOCKET, S_IRWXU | S_IRWXG | S_IRWXO)) {
		syslog(LOG_ERR, "chmod() failed: %m");
		cleanup_exit(1);
	}

	/* Raise the rlimit for file descriptors... */
	rl.rlim_max = MAX_DESCRIPTORS;
	rl.rlim_cur = MAX_DESCRIPTORS;
	setrlimit(RLIMIT_NOFILE, &rl);

}

static void dropprivs(void)
{
	cap_t new_caps;

	new_caps = cap_init();
	if (cap_set_proc(new_caps)) {
		syslog(LOG_ERR, "Error dropping capabilities, aborting: %s\n",
			 strerror(errno));
		cleanup_exit(-1);
	}
	cap_free(new_caps);
}

static void usage(char *program)
{
	printf("%s [-f] [-h] \n", program);
}

int
main(int argc, char *argv[])
{
	int opt;
	int do_fork = 1;
	while ((opt = getopt(argc, argv, "hf")) > 0) {
		switch (opt) {
		case 'f':
			do_fork = 0;
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
			break;
		case '?':
			usage(argv[0]);
			exit(-1);
		}
	}

#ifndef DEBUG
	/* Make sure we are root */
	if (getuid() != 0) {
		syslog(LOG_ERR, "You must be root to run this program.\n");
		return 4;
	}
#endif

	openlog(SETRANSD_PROGNAME, 0, LOG_DAEMON);
	syslog(LOG_NOTICE, "%s starting", argv[0]);

	initialize();

#ifndef DEBUG
	dropprivs();

	/* run in the background as a daemon */
	if (do_fork && daemon(0, 0)) {
		syslog(LOG_ERR, "daemon() failed: %m");
		cleanup_exit(1);
	}
#endif

	syslog(LOG_NOTICE, "%s initialized", argv[0]);
	process_connections();

	/* we should never get here */
	return 1;
}

