#ifndef _RESTORECON_H_
#define _RESTORECON_H_

#include <sys/types.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * selinux_restorecon - Relabel files.
 * @pathname: specifies file/directory to relabel.
 * @restorecon_flags: specifies the actions to be performed when relabeling.
 *
 * selinux_restorecon(3) will automatically call
 * selinux_restorecon_default_handle(3) and selinux_restorecon_set_sehandle(3)
 * first time through to set the selabel_open(3) parameters to use the
 * currently loaded policy file_contexts and request their computed digest.
 *
 * Should other selabel_open(3) parameters be required see
 * selinux_restorecon_set_sehandle(3).
 */
extern int selinux_restorecon(const char *pathname,
				    unsigned int restorecon_flags);
/*
 * restorecon_flags options
 */
/* Force the checking of labels even if the stored SHA1
 * digest matches the specfiles SHA1 digest. */
#define SELINUX_RESTORECON_IGNORE_DIGEST		1
/* Do not change file labels */
#define SELINUX_RESTORECON_NOCHANGE			2
/* If set set change file label to that in spec file.
 * If not only change type component to that in spec file. */
#define SELINUX_RESTORECON_SET_SPECFILE_CTX		4
/* Recursively descend directories */
#define SELINUX_RESTORECON_RECURSE			8
/* Log changes to selinux log. Note that if VERBOSE and
 * PROGRESS are set, then PROGRESS will take precedence. */
#define SELINUX_RESTORECON_VERBOSE			16
/* Show progress by printing * to stdout every 1000 files */
#define SELINUX_RESTORECON_PROGRESS			32
/* Convert passed-in pathname to canonical pathname */
#define SELINUX_RESTORECON_REALPATH			64
/* Prevent descending into directories that have a different
 * device number than the pathname from which the descent began */
#define SELINUX_RESTORECON_XDEV				128

/**
 * selinux_restorecon_set_sehandle - Set the global fc handle.
 * @handle: specifies handle to set as the global fc handle.
 *
 * Called by a process that has already called selabel_open(3) with it's
 * required parameters, or if selinux_restorecon_default_handle(3) has been
 * called to set the default selabel_open(3) parameters.
 */
extern void selinux_restorecon_set_sehandle(struct selabel_handle *hndl);

/**
 * selinux_restorecon_default_handle - Sets default selabel_open(3) parameters
 *				       to use the currently loaded policy and
 *				       file_contexts, also requests the digest.
 */
extern struct selabel_handle *selinux_restorecon_default_handle(void);

/**
 * selinux_restorecon_set_exclude_list - Add a list of files or
 *					 directories that are to be excluded
 *					 from relabeling.
 * @exclude_list: containing a NULL terminated list of one or more
 *		  directories or files not to be relabeled.
 */
extern void selinux_restorecon_set_exclude_list(const char **exclude_list);

#ifdef __cplusplus
}
#endif
#endif
