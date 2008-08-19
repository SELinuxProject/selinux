/*
 * Callbacks for user-supplied memory allocation, supplemental
 * auditing, and locking routines.
 *
 * Author : Eamon Walsh <ewalsh@epoch.ncsc.mil>
 *
 * Netlink code derived in part from sample code by
 * James Morris <jmorris@redhat.com>.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include "selinux_netlink.h"
#include "avc_internal.h"

#ifndef NETLINK_SELINUX
#define NETLINK_SELINUX 7
#endif

/* callback pointers */
void *(*avc_func_malloc) (size_t) = NULL;
void (*avc_func_free) (void *) = NULL;

void (*avc_func_log) (const char *, ...) = NULL;
void (*avc_func_audit) (void *, security_class_t, char *, size_t) = NULL;

int avc_using_threads = 0;
void *(*avc_func_create_thread) (void (*)(void)) = NULL;
void (*avc_func_stop_thread) (void *) = NULL;

void *(*avc_func_alloc_lock) (void) = NULL;
void (*avc_func_get_lock) (void *) = NULL;
void (*avc_func_release_lock) (void *) = NULL;
void (*avc_func_free_lock) (void *) = NULL;

/* message prefix string and avc enforcing mode */
char avc_prefix[AVC_PREFIX_SIZE] = "uavc";
int avc_enforcing = 1;
int avc_netlink_trouble = 0;

/* netlink socket code */
static int fd;

int avc_netlink_open(int blocking)
{
	int len, rc = 0;
	struct sockaddr_nl addr;

	fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_SELINUX);
	if (fd < 0) {
		rc = fd;
		goto out;
	}
	
	fcntl(fd, F_SETFD, FD_CLOEXEC);
	if (!blocking && fcntl(fd, F_SETFL, O_NONBLOCK)) {
		close(fd);
		rc = -1;
		goto out;
	}

	len = sizeof(addr);

	memset(&addr, 0, len);
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = SELNL_GRP_AVC;

	if (bind(fd, (struct sockaddr *)&addr, len) < 0) {
		close(fd);
		rc = -1;
		goto out;
	}
      out:
	return rc;
}

void avc_netlink_close(void)
{
	close(fd);
}

int avc_netlink_check_nb(void)
{
	int rc;
	struct sockaddr_nl nladdr;
	socklen_t nladdrlen = sizeof nladdr;
	char buf[1024];
	struct nlmsghdr *nlh;

	while (1) {
		rc = recvfrom(fd, buf, sizeof(buf), 0,
			      (struct sockaddr *)&nladdr, &nladdrlen);
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			if (errno != EAGAIN) {
				avc_log("%s:  socket error during read: %d\n",
					avc_prefix, errno);
			} else {
				errno = 0;
				rc = 0;
			}
			goto out;
		}

		if (nladdrlen != sizeof nladdr) {
			avc_log
			    ("%s:  warning: netlink address truncated, len %d?\n",
			     avc_prefix, nladdrlen);
			rc = -1;
			goto out;
		}

		if (nladdr.nl_pid) {
			avc_log
			    ("%s:  warning: received spoofed netlink packet from: %d\n",
			     avc_prefix, nladdr.nl_pid);
			continue;
		}

		if (rc == 0) {
			avc_log("%s:  warning: received EOF on socket\n",
				avc_prefix);
			goto out;
		}

		nlh = (struct nlmsghdr *)buf;

		if (nlh->nlmsg_flags & MSG_TRUNC
		    || nlh->nlmsg_len > (unsigned)rc) {
			avc_log("%s:  warning: incomplete netlink message\n",
				avc_prefix);
			goto out;
		}

		rc = 0;
		switch (nlh->nlmsg_type) {
		case NLMSG_ERROR:{
				struct nlmsgerr *err = NLMSG_DATA(nlh);

				/* Netlink ack */
				if (err->error == 0)
					break;

				errno = -err->error;
				avc_log("%s:  netlink error: %d\n", avc_prefix,
					errno);
				rc = -1;
				goto out;
			}

		case SELNL_MSG_SETENFORCE:{
				struct selnl_msg_setenforce *msg =
				    NLMSG_DATA(nlh);
				avc_log
				    ("%s:  received setenforce notice (enforcing=%d)\n",
				     avc_prefix, msg->val);
				avc_enforcing = msg->val;
				if (avc_enforcing && (rc = avc_ss_reset(0)) < 0) {
					avc_log
					    ("%s:  cache reset returned %d (errno %d)\n",
					     avc_prefix, rc, errno);
					goto out;
				}
				break;
			}

		case SELNL_MSG_POLICYLOAD:{
				struct selnl_msg_policyload *msg =
				    NLMSG_DATA(nlh);
				avc_log
				    ("%s:  received policyload notice (seqno=%d)\n",
				     avc_prefix, msg->seqno);
				rc = avc_ss_reset(msg->seqno);
				if (rc < 0) {
					avc_log
					    ("%s:  cache reset returned %d (errno %d)\n",
					     avc_prefix, rc, errno);
					goto out;
				}
				break;
			}

		default:
			avc_log("%s:  warning: unknown netlink message %d\n",
				avc_prefix, nlh->nlmsg_type);
		}
	}
      out:
	return rc;
}

/* run routine for the netlink listening thread */
void avc_netlink_loop(void)
{
	int ret;
	struct sockaddr_nl nladdr;
	socklen_t nladdrlen = sizeof nladdr;
	char buf[1024];
	struct nlmsghdr *nlh;

	while (1) {
		ret =
		    recvfrom(fd, buf, sizeof(buf), 0,
			     (struct sockaddr *)&nladdr, &nladdrlen);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			avc_log("%s:  netlink thread: recvfrom: error %d\n",
				avc_prefix, errno);
			goto out;
		}

		if (nladdrlen != sizeof nladdr) {
			avc_log
			    ("%s:  warning: netlink address truncated, len %d?\n",
			     avc_prefix, nladdrlen);
			ret = -1;
			goto out;
		}

		if (nladdr.nl_pid) {
			avc_log
			    ("%s:  warning: received spoofed netlink packet from: %d\n",
			     avc_prefix, nladdr.nl_pid);
			continue;
		}

		if (ret == 0) {
			avc_log("%s:  netlink thread: received EOF on socket\n",
				avc_prefix);
			goto out;
		}

		nlh = (struct nlmsghdr *)buf;

		if (nlh->nlmsg_flags & MSG_TRUNC
		    || nlh->nlmsg_len > (unsigned)ret) {
			avc_log
			    ("%s:  netlink thread: incomplete netlink message\n",
			     avc_prefix);
			goto out;
		}

		switch (nlh->nlmsg_type) {
		case NLMSG_ERROR:{
				struct nlmsgerr *err = NLMSG_DATA(nlh);

				/* Netlink ack */
				if (err->error == 0)
					break;

				avc_log("%s:  netlink thread: msg: error %d\n",
					avc_prefix, -err->error);
				goto out;
			}

		case SELNL_MSG_SETENFORCE:{
				struct selnl_msg_setenforce *msg =
				    NLMSG_DATA(nlh);
				avc_log
				    ("%s:  received setenforce notice (enforcing=%d)\n",
				     avc_prefix, msg->val);
				avc_enforcing = msg->val;
				if (avc_enforcing && (ret = avc_ss_reset(0)) < 0) {
					avc_log
					    ("%s:  cache reset returned %d (errno %d)\n",
					     avc_prefix, ret, errno);
					goto out;
				}
				break;
			}

		case SELNL_MSG_POLICYLOAD:{
				struct selnl_msg_policyload *msg =
				    NLMSG_DATA(nlh);
				avc_log
				    ("%s:  received policyload notice (seqno=%d)\n",
				     avc_prefix, msg->seqno);
				ret = avc_ss_reset(msg->seqno);
				if (ret < 0) {
					avc_log
					    ("%s:  netlink thread: cache reset returned %d (errno %d)\n",
					     avc_prefix, ret, errno);
					goto out;
				}
				break;
			}

		default:
			avc_log
			    ("%s:  netlink thread: warning: unknown msg type %d\n",
			     avc_prefix, nlh->nlmsg_type);
		}
	}
      out:
	close(fd);
	avc_netlink_trouble = 1;
	avc_log("%s:  netlink thread: errors encountered, terminating\n",
		avc_prefix);
}
