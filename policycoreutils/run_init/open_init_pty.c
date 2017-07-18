/*                               -*- Mode: C -*- 
 * open_init_pty.c --- 
 * Author           : Manoj Srivastava ( srivasta@glaurung.internal.golden-gryphon.com ) 
 * Created On       : Fri Jan 14 10:48:28 2005
 * Created On Node  : glaurung.internal.golden-gryphon.com
 * Last Modified By : Manoj Srivastava
 * Last Modified On : Thu Sep 15 00:57:00 2005
 * Last Machine Used: glaurung.internal.golden-gryphon.com
 * Update Count     : 92
 * Status           : Unknown, Use with caution!
 * HISTORY          : 
 * Description      : 
 *
 * Distributed under the terms of the GNU General Public License v2
 *
 * open_init_pty
 *
 * SYNOPSIS:
 *
 * This program allows a systems administrator to execute daemons
 * which need to work in the initrc domain, and which need to have
 * pty's as system_u:system_r:initrc_t
 *
 * USAGE:
 *
 * * arch-tag: a5583d39-72b9-4cdf-ba1b-5678ea4cbe20
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#include <sysexits.h>

#include <pty.h>		/* for forkpty */
#include <termios.h>
#include <fcntl.h>

#include <sys/select.h>
#include <sys/wait.h>


#define MAXRETR 3		/* The max number of IO retries on a fd */
#define BUFSIZE 2048		/* The ring buffer size */

static struct termios saved_termios;
static int saved_fd = -1;
static enum { RESET, RAW, CBREAK } tty_state = RESET;

static int tty_semi_raw(int fd)
{
	struct termios buf;

	if (tty_state == RESET) {
		if (tcgetattr(fd, &saved_termios) < 0) {
			return -1;
		}
	}

	buf = saved_termios;
	/*
	 * echo off, canonical mode off, extended input processing off,
	 * signal chars off 
	 */
	buf.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);
	/*
	 * no SIGINT on break, CR-to-NL off, input parity check off, do not
	 * strip 8th bit on input,output flow control off
	 */
	buf.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
	/* Clear size bits, parity checking off */
	buf.c_cflag &= ~(CSIZE | PARENB);
	/* set 8 bits/char */
	buf.c_cflag |= CS8;
	/* Output processing off 
	   buf.c_oflag    &= ~(OPOST); */

	buf.c_cc[VMIN] = 1;	/* one byte at a time, no timer */
	buf.c_cc[VTIME] = 0;
	if (tcsetattr(fd, TCSANOW, &buf) < 0) {
		return -1;
	}			/* end of if(tcsetattr(fileno(stdin), TCSANOW, &buf) < 0) */
	tty_state = RAW;
	saved_fd = fd;
	return 0;
}

static void tty_atexit(void)
{
	if (tty_state != CBREAK && tty_state != RAW) {
		return;
	}

	if (tcsetattr(saved_fd, TCSANOW, &saved_termios) < 0) {
		return;
	}
	tty_state = RESET;
	return;
}


/* The simple ring buffer */
struct ring_buffer {
	char *buf; /* pointer to buffer memory */
	char *wptr;
	char *rptr;
	size_t size; /* the number of bytes allocated for buf */
	size_t count;
};

static void rb_init(struct ring_buffer *b, char *buf, size_t size)
{
	b->buf = b->wptr = b->rptr = buf;
	b->size = size;
	b->count = 0;
}

static int rb_isempty(struct ring_buffer *b)
{
	return b->count == 0;
}

/* return the unused space size in the buffer */
static size_t rb_space(struct ring_buffer *b)
{
	if (b->rptr > b->wptr)
		return b->rptr - b->wptr;

	if (b->rptr < b->wptr || b->count == 0)
		return b->buf + b->size - b->wptr;

	return 0; /* should not hit this */
}

/* return the used space in the buffer */
static size_t rb_chunk_size(struct ring_buffer *b)
{
	if (b->rptr < b->wptr)
		return b->wptr - b->rptr;

	if (b->rptr > b->wptr || b->count > 0)
		return b->buf + b->size - b->rptr;

	return 0; /* should not hit this */
}

/* read from fd and write to buffer memory */
static ssize_t rb_read(struct ring_buffer *b, int fd)
{
	ssize_t n = read(fd, b->wptr, rb_space(b));
	if (n <= 0)
		return n;

	b->wptr += n;
	b->count += n;
	if (b->buf + b->size <= b->wptr)
		b->wptr = b->buf;

	return n;
}

static ssize_t rb_write(struct ring_buffer *b, int fd)
{
	ssize_t n = write(fd, b->rptr, rb_chunk_size(b));
	if (n <= 0)
		return n;

	b->rptr += n;
	b->count -= n;
	if (b->buf + b->size <= b->rptr)
		b->rptr = b->buf;

	return n;
}

static void setfd_nonblock(int fd)
{
	int fsflags = fcntl(fd, F_GETFL);

	if (fsflags < 0) {
		fprintf(stderr, "fcntl(%d, F_GETFL): %s\n", fd, strerror(errno));
		exit(EX_IOERR);
	}

	if (fcntl(fd, F_SETFL, fsflags | O_NONBLOCK) < 0) {
		fprintf(stderr, "fcntl(%d, F_SETFL, ... | O_NONBLOCK): %s\n", fd, strerror(errno));
		exit(EX_IOERR);
	}
}

static void setfd_block(int fd)
{
	int fsflags = fcntl(fd, F_GETFL);

	if (fsflags < 0) {
		fprintf(stderr, "fcntl(%d, F_GETFL): %s\n", fd, strerror(errno));
		exit(EX_IOERR);
	}

	if (fcntl(fd, F_SETFL, fsflags & ~O_NONBLOCK) < 0) {
		fprintf(stderr, "fcntl(%d, F_SETFL, ... & ~O_NONBLOCK): %s\n", fd, strerror(errno));
		exit(EX_IOERR);
	}
}

static void setfd_atexit(void)
{
	setfd_block(STDIN_FILENO);
	setfd_block(STDOUT_FILENO);
	return;
}

static void sigchld_handler(int asig __attribute__ ((unused)))
{
}

int main(int argc, char *argv[])
{
	pid_t child_pid;
	int child_exit_status;
	struct termios tty_attr;
	struct winsize window_size;
	int pty_master;

	/* for select */
	fd_set readfds;
	fd_set writefds;

	unsigned err_n_rpty = 0;
	unsigned err_n_wpty = 0;
	unsigned err_n_stdin = 0;
	unsigned err_n_stdout = 0;

	int done = 0;

	/* the ring buffers */
	char inbuf_mem[BUFSIZE];
	char outbuf_mem[BUFSIZE];
	struct ring_buffer inbuf;
	struct ring_buffer outbuf;
	rb_init(&inbuf, inbuf_mem, sizeof(inbuf_mem));
	rb_init(&outbuf, outbuf_mem, sizeof(outbuf_mem));

	if (argc == 1) {
		printf("usage: %s PROGRAM [ARGS]...\n", argv[0]);
		exit(1);
	}

	/* We need I/O calls to fail with EINTR on SIGCHLD... */
	if (signal(SIGCHLD, sigchld_handler) == SIG_ERR) {
		perror("signal(SIGCHLD,...)");
		exit(EX_OSERR);
	}

	if (isatty(STDIN_FILENO)) {
		/* get terminal parameters associated with stdout */
		if (tcgetattr(STDOUT_FILENO, &tty_attr) < 0) {
			perror("tcgetattr(stdout,...)");
			exit(EX_OSERR);
		}

		/* get window size */
		if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &window_size) < 0) {
			perror("ioctl(stdout,...)");
			exit(1);
		}

		child_pid = forkpty(&pty_master, NULL, &tty_attr, &window_size);
	} else { /* not interactive */
		child_pid = forkpty(&pty_master, NULL, NULL, NULL);
	}

	if (child_pid < 0) {
		perror("forkpty()");
		exit(EX_OSERR);
	}
	if (child_pid == 0) { /* in the child */
		struct termios s_tty_attr;
		if (tcgetattr(STDIN_FILENO, &s_tty_attr)) {
			perror("tcgetattr(stdin,...)");
			exit(EXIT_FAILURE);
		}
		/* Turn off echo */
		s_tty_attr.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
		/* Also turn of NL to CR?LF on output */
		s_tty_attr.c_oflag &= ~(ONLCR);
		if (tcsetattr(STDIN_FILENO, TCSANOW, &s_tty_attr)) {
			perror("tcsetattr(stdin,...)");
			exit(EXIT_FAILURE);
		}

		if (execvp(argv[1], argv + 1)) {
			perror("execvp()");
			exit(EXIT_FAILURE);
		}
	}

	/* Non blocking mode for all file descriptors. */
	setfd_nonblock(pty_master);
	setfd_nonblock(STDIN_FILENO);
	setfd_nonblock(STDOUT_FILENO);
	if (atexit(setfd_atexit) < 0) {
		perror("atexit()");
		exit(EXIT_FAILURE);
	}

	if (isatty(STDIN_FILENO)) {
		if (tty_semi_raw(STDIN_FILENO) < 0) {
			perror("tty_semi_raw(stdin)");
		}
		if (atexit(tty_atexit) < 0) {
			perror("atexit()");
		}
	}

	do {
		/* Accept events only on fds, that we can handle now. */
		int do_select = 0;
		FD_ZERO(&readfds);
		FD_ZERO(&writefds);

		if (rb_space(&outbuf) > 0 && err_n_rpty < MAXRETR) {
			FD_SET(pty_master, &readfds);
			do_select = 1;
		}

		if (!rb_isempty(&inbuf) && err_n_wpty < MAXRETR) {
			FD_SET(pty_master, &writefds);
			do_select = 1;
		}

		if (rb_space(&inbuf) > 0 && err_n_stdin < MAXRETR) {
			FD_SET(STDIN_FILENO, &readfds);
			do_select = 1;
		}

		if (!rb_isempty(&outbuf) && err_n_stdout < MAXRETR) {
			FD_SET(STDOUT_FILENO, &writefds);
			do_select = 1;
		}

		if (!do_select) {
#ifdef DEBUG
			fprintf(stderr, "No I/O job for us, calling waitpid()...\n");
#endif
			while (waitpid(child_pid, &child_exit_status, 0) < 0)
			{
				/* nothing */
			}
			break;
		}

		errno = 0;
		int select_rc = select(pty_master + 1, &readfds, &writefds, NULL, NULL);
		if (select_rc < 0 && errno != EINTR) {
			perror("select()");
			exit(EX_IOERR);
		}
#ifdef DEBUG
		fprintf(stderr, "select() returned %d\n", select_rc);
#endif

		if (FD_ISSET(STDOUT_FILENO, &writefds)) {
#ifdef DEBUG
			fprintf(stderr, "stdout can be written\n");
#endif
			ssize_t n = rb_write(&outbuf, STDOUT_FILENO);
			if (n <= 0 && n != EINTR && n != EAGAIN)
				err_n_stdout++;
#ifdef DEBUG
			if (n >= 0)
				fprintf(stderr, "%d bytes written into stdout\n", n);
			else
				perror("write(stdout,...)");
#endif
		}

		if (FD_ISSET(pty_master, &writefds)) {
#ifdef DEBUG
			fprintf(stderr, "pty_master can be written\n");
#endif
			ssize_t n = rb_write(&inbuf, pty_master);
			if (n <= 0 && n != EINTR && n != EAGAIN)
				err_n_wpty++;
#ifdef DEBUG
			if (n >= 0)
				fprintf(stderr, "%d bytes written into pty_master\n", n);
			else
				perror("write(pty_master,...)");
#endif
		}

		if (FD_ISSET(STDIN_FILENO, &readfds)) {
#ifdef DEBUG
			fprintf(stderr, "stdin can be read\n");
#endif
			ssize_t n = rb_read(&inbuf, STDIN_FILENO);
			if (n <= 0 && n != EINTR && n != EAGAIN)
				err_n_stdin++;
#ifdef DEBUG
			if (n >= 0)
				fprintf(stderr, "%d bytes read from stdin\n", n);
			else
				perror("read(stdin,...)");
#endif
		}

		if (FD_ISSET(pty_master, &readfds)) {
#ifdef DEBUG
			fprintf(stderr, "pty_master can be read\n");
#endif
			ssize_t n = rb_read(&outbuf, pty_master);
			if (n <= 0 && n != EINTR && n != EAGAIN)
				err_n_rpty++;
#ifdef DEBUG
			if (n >= 0)
				fprintf(stderr, "%d bytes read from pty_master\n", n);
			else
				perror("read(pty_master,...)");
#endif
		}

		if (!done && waitpid(child_pid, &child_exit_status, WNOHANG) > 0)
			done = 1;

	} while (!done
		|| !(rb_isempty(&inbuf) || err_n_wpty >= MAXRETR)
		|| !(rb_isempty(&outbuf) || err_n_stdout >= MAXRETR));

#ifdef DEBUG
	fprintf(stderr, "inbuf: %u bytes left, outbuf: %u bytes left\n", inbuf.count, outbuf.count);
	fprintf(stderr, "err_n_rpty=%u, err_n_wpty=%u, err_n_stdin=%u, err_n_stdout=%u\n",
		err_n_rpty, err_n_wpty, err_n_stdin, err_n_stdout);
#endif

	if (WIFEXITED(child_exit_status))
		exit(WEXITSTATUS(child_exit_status));
	else if (WIFSIGNALED(child_exit_status))
		exit(128 + WTERMSIG(child_exit_status));

	exit(EXIT_FAILURE);
}
