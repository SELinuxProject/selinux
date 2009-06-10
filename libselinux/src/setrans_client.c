/* Author: Trusted Computer Solutions, Inc. 
 * 
 * Modified:
 * Yuichi Nakamura <ynakam@hitachisoft.jp> 
 - Stubs are used when DISABLE_SETRANS is defined, 
   it is to reduce size for such as embedded devices.
*/

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <stdlib.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <pthread.h>
#include "dso.h"
#include "selinux_internal.h"
#include "setrans_internal.h"

#ifndef DISABLE_SETRANS
static int mls_enabled = -1;

// Simple cache
static pthread_key_t prev_t2r_trans_key;
static pthread_key_t prev_t2r_raw_key;
static pthread_key_t prev_r2t_trans_key;
static pthread_key_t prev_r2t_raw_key;
static pthread_key_t prev_r2c_trans_key;
static pthread_key_t prev_r2c_raw_key;
static pthread_once_t make_keys_once = PTHREAD_ONCE_INIT;

/*
 * setransd_open
 *
 * This function opens a socket to the setransd.
 * Returns:  on success, a file descriptor ( >= 0 ) to the socket
 *           on error, a negative value
 */
static int setransd_open(void)
{
	struct sockaddr_un addr;
	int fd;
#ifdef SOCK_CLOEXEC
	fd = socket(PF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
	if (fd < 0 && errno == EINVAL)
#endif
	{
		fd = socket(PF_UNIX, SOCK_STREAM, 0);
		if (fd >= 0)
			fcntl(fd, F_SETFD, FD_CLOEXEC);
	}
	if (fd < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, SETRANS_UNIX_SOCKET, sizeof(addr.sun_path));
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

/* Returns: 0 on success, <0 on failure */
static int
send_request(int fd, uint32_t function, const char *data1, const char *data2)
{
	struct msghdr msgh;
	struct iovec iov[5];
	uint32_t data1_size;
	uint32_t data2_size;
	ssize_t count, expected;
	unsigned int i;

	if (fd < 0)
		return -1;

	if (!data1)
		data1 = "";
	if (!data2)
		data2 = "";

	data1_size = strlen(data1) + 1;
	data2_size = strlen(data2) + 1;

	iov[0].iov_base = &function;
	iov[0].iov_len = sizeof(function);
	iov[1].iov_base = &data1_size;
	iov[1].iov_len = sizeof(data1_size);
	iov[2].iov_base = &data2_size;
	iov[2].iov_len = sizeof(data2_size);
	iov[3].iov_base = (char *)data1;
	iov[3].iov_len = data1_size;
	iov[4].iov_base = (char *)data2;
	iov[4].iov_len = data2_size;
	memset(&msgh, 0, sizeof(msgh));
	msgh.msg_iov = iov;
	msgh.msg_iovlen = sizeof(iov) / sizeof(iov[0]);

	expected = 0;
	for (i = 0; i < sizeof(iov) / sizeof(iov[0]); i++)
		expected += iov[i].iov_len;

	while (((count = sendmsg(fd, &msgh, MSG_NOSIGNAL)) < 0)
	       && (errno == EINTR)) ;
	if (count < 0 || count != expected)
		return -1;

	return 0;
}

/* Returns: 0 on success, <0 on failure */
static int
receive_response(int fd, uint32_t function, char **outdata, int32_t * ret_val)
{
	struct iovec resp_hdr[3];
	uint32_t func;
	uint32_t data_size;
	char *data;
	struct iovec resp_data;
	ssize_t count;

	if (fd < 0)
		return -1;

	resp_hdr[0].iov_base = &func;
	resp_hdr[0].iov_len = sizeof(func);
	resp_hdr[1].iov_base = &data_size;
	resp_hdr[1].iov_len = sizeof(data_size);
	resp_hdr[2].iov_base = ret_val;
	resp_hdr[2].iov_len = sizeof(*ret_val);

	while (((count = readv(fd, resp_hdr, 3)) < 0) && (errno == EINTR)) ;
	if (count != (sizeof(func) + sizeof(data_size) + sizeof(*ret_val))) {
		return -1;
	}

	if (func != function || !data_size || data_size > MAX_DATA_BUF) {
		return -1;
	}

	data = malloc(data_size);
	if (!data) {
		return -1;
	}

	resp_data.iov_base = data;
	resp_data.iov_len = data_size;

	while (((count = readv(fd, &resp_data, 1))) < 0 && (errno == EINTR)) ;
	if (count < 0 || (uint32_t) count != data_size ||
	    data[data_size - 1] != '\0') {
		free(data);
		return -1;
	}
	*outdata = data;
	return 0;
}

static int raw_to_trans_context(char *raw, char **transp)
{
	int ret;
	int32_t ret_val;
	int fd;

	*transp = NULL;

	fd = setransd_open();
	if (fd < 0)
		return fd;

	ret = send_request(fd, RAW_TO_TRANS_CONTEXT, raw, NULL);
	if (ret)
		goto out;

	ret = receive_response(fd, RAW_TO_TRANS_CONTEXT, transp, &ret_val);
	if (ret)
		goto out;

	ret = ret_val;
      out:
	close(fd);
	return ret;
}

static int trans_to_raw_context(char *trans, char **rawp)
{
	int ret;
	int32_t ret_val;
	int fd;

	*rawp = NULL;

	fd = setransd_open();
	if (fd < 0)
		return fd;
	ret = send_request(fd, TRANS_TO_RAW_CONTEXT, trans, NULL);
	if (ret)
		goto out;

	ret = receive_response(fd, TRANS_TO_RAW_CONTEXT, rawp, &ret_val);
	if (ret)
		goto out;

	ret = ret_val;
      out:
	close(fd);
	return ret;
}

static int raw_context_to_color(char *raw, char **colors)
{
	int ret;
	int32_t ret_val;
	int fd;

	fd = setransd_open();
	if (fd < 0)
		return fd;

	ret = send_request(fd, RAW_CONTEXT_TO_COLOR, raw, NULL);
	if (ret)
		goto out;

	ret = receive_response(fd, RAW_CONTEXT_TO_COLOR, colors, &ret_val);
	if (ret)
		goto out;

	ret = ret_val;
out:
	close(fd);
	return ret;
}

static void delete_value(void *value)
{
	free(value);
}

static void drop_cached_value(pthread_key_t cache_key)
{
	void *value;
	value = pthread_getspecific(cache_key);
	if (value) {
		pthread_setspecific(cache_key, NULL);
		delete_value(value);
	}
}

hidden void fini_context_translations(void)
{
/* this is not necessary but if we are single threaded
   we can free the data earlier than on exit */
	drop_cached_value(prev_r2t_trans_key);
	drop_cached_value(prev_r2t_raw_key);
	drop_cached_value(prev_t2r_trans_key);
	drop_cached_value(prev_t2r_raw_key);
	drop_cached_value(prev_r2c_trans_key);
	drop_cached_value(prev_r2c_raw_key);
}

static void make_keys(void)
{
	(void)pthread_key_create(&prev_t2r_trans_key, delete_value);
	(void)pthread_key_create(&prev_t2r_raw_key, delete_value);
	(void)pthread_key_create(&prev_r2t_trans_key, delete_value);
	(void)pthread_key_create(&prev_r2t_raw_key, delete_value);
	(void)pthread_key_create(&prev_r2c_trans_key, delete_value);
	(void)pthread_key_create(&prev_r2c_raw_key, delete_value);
}

hidden int init_context_translations(void)
{
	mls_enabled = is_selinux_mls_enabled();
	(void)pthread_once(&make_keys_once, make_keys);
	return 0;
}

static void *match_cached_value(pthread_key_t cache_from,
			 pthread_key_t cache_to,
			 const char *match_from)
{
	void *from, *to;

	from = pthread_getspecific(cache_from);
	to = pthread_getspecific(cache_to);
	if (from && strcmp(from, match_from) == 0) {
		return strdup(to);
	} else {
		pthread_setspecific(cache_from, NULL);
		delete_value(from);
		pthread_setspecific(cache_to, NULL);
		delete_value(to);
		errno = 0;
		return NULL;
	}
}

void set_cached_value(pthread_key_t cache_from,
		      pthread_key_t cache_to,
		      void *from,
		      void *to)
{
	from = strdup(from);
	if (from == NULL)
		return;

	to = strdup(to);
	if (to == NULL) {
		free(from);
		return;
	}

	pthread_setspecific(cache_from, from);
	pthread_setspecific(cache_to, to);
}

int selinux_trans_to_raw_context(security_context_t trans,
				 security_context_t * rawp)
{
	if (!trans) {
		*rawp = NULL;
		return 0;
	}

	if (!mls_enabled) {
		*rawp = strdup(trans);
		goto out;
	}

	if ((*rawp = match_cached_value(prev_t2r_trans_key, prev_t2r_raw_key, trans)) == NULL
	    && errno == 0) {
		if (trans_to_raw_context(trans, rawp))
			*rawp = strdup(trans);
		if (*rawp) {
			set_cached_value(prev_t2r_trans_key, prev_t2r_raw_key,
					 trans, *rawp);
		}
	}
      out:
	return *rawp ? 0 : -1;
}

hidden_def(selinux_trans_to_raw_context)

int selinux_raw_to_trans_context(security_context_t raw,
				 security_context_t * transp)
{
	if (!raw) {
		*transp = NULL;
		return 0;
	}

	if (!mls_enabled) {
		*transp = strdup(raw);
		goto out;
	}

	if ((*transp = match_cached_value(prev_r2t_raw_key, prev_r2t_trans_key, raw)) == NULL
	    && errno == 0) {
		if (raw_to_trans_context(raw, transp))
			*transp = strdup(raw);
		if (*transp) {
			set_cached_value(prev_r2t_raw_key, prev_r2t_trans_key,
					 raw, *transp);
		}
	}
      out:
	return *transp ? 0 : -1;
}

hidden_def(selinux_raw_to_trans_context)

int selinux_raw_context_to_color(security_context_t raw, char **transp)
{
	if (!raw) {
		*transp = NULL;
		return -1;
	}

	if ((*transp = match_cached_value(prev_r2c_raw_key, prev_r2c_trans_key, raw)) == NULL
	    && errno == 0) {
		if (raw_context_to_color(raw, transp))
			return -1;
		if (*transp) {
			set_cached_value(prev_r2c_raw_key, prev_r2c_trans_key,
					 raw, *transp);
		}
	}
	return *transp ? 0 : -1;
}

hidden_def(selinux_raw_context_to_color)
#else /*DISABLE_SETRANS*/

hidden void fini_context_translations(void)
{
}

hidden int init_context_translations(void)
{
	return 0;
}

int selinux_trans_to_raw_context(security_context_t trans,
				 security_context_t * rawp)
{
	if (!trans) {
		*rawp = NULL;
		return 0;
	}

	*rawp = strdup(trans);
	
	return *rawp ? 0 : -1;
}

hidden_def(selinux_trans_to_raw_context)

int selinux_raw_to_trans_context(security_context_t raw,
				 security_context_t * transp)
{
	if (!raw) {
		*transp = NULL;
		return 0;
	}
	*transp = strdup(raw);
	
	return *transp ? 0 : -1;
}

hidden_def(selinux_raw_to_trans_context)
#endif /*DISABLE_SETRANS*/
