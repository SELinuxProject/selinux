/************************************************************************
 *
 * run_init
 *
 * SYNOPSIS:
 *
 * This program allows a user to run an /etc/init.d script in the proper context.
 *
 * USAGE:
 *
 * run_init <script> <args>
 *
 * BUILD OPTIONS:
 *
 * option USE_PAM:
 *
 * Set the USE_PAM constant if you want to authenticate users via PAM.
 * If USE_PAM is not set, users will be authenticated via direct
 * access to the shadow password file.
 *
 * If you decide to use PAM must be told how to handle run_init.  A
 * good rule-of-thumb might be to tell PAM to handle run_init in the
 * same way it handles su, except that you should remove the pam_rootok.so
 * entry so that even root must re-authenticate to run the init scripts
 * in the proper context.
 *
 * If you choose not to use PAM, make sure you have a shadow passwd file
 * in /etc/shadow.  You can use a simlink if your shadow passwd file
 * lives in another directory.  Example:
 *   su
 *   cd /etc
 *   ln -s /etc/auth/shadow shadow
 *
 * If you decide not to use PAM, you will also have to make run_init
 * setuid root, so that it can read the shadow passwd file.
 * 
 *
 *************************************************************************/

#include <stdio.h>
#include <stdlib.h>		/* for malloc(), realloc(), free() */
#include <pwd.h>		/* for getpwuid() */
#include <sys/types.h>		/* to make getuid() and getpwuid() happy */
#include <sys/wait.h>		/* for wait() */
#include <sys/stat.h>		/* for struct stat and friends */
#include <getopt.h>		/* for getopt_long() form of getopt() */
#include <selinux/selinux.h>
#include <selinux/get_default_type.h>
#include <selinux/context.h>	/* for context-mangling functions */
#include <fcntl.h>
#include <ctype.h>
#include <limits.h>
#ifdef USE_AUDIT
#include <libaudit.h>
#endif
#ifdef USE_NLS
#include <libintl.h>
#include <locale.h>
#define _(msgid) gettext (msgid)
#else
#define _(msgid) (msgid)
#endif
#ifndef PACKAGE
#define PACKAGE "policycoreutils"	/* the name of this package lang translation */
#endif
/* USAGE_STRING describes the command-line args of this program. */
#define USAGE_STRING _("USAGE: run_init <script> <args ...>\n\
  where: <script> is the name of the init script to run,\n\
         <args ...> are the arguments to that script.")

#define CONTEXT_FILE "initrc_context"
#ifdef USE_PAM

/************************************************************************
 *
 * All PAM code goes in this section.
 *
 ************************************************************************/

#include <unistd.h>		/* for getuid(), exit(), getopt() */

#include <security/pam_appl.h>	/* for PAM functions */
#include <security/pam_misc.h>	/* for misc_conv PAM utility function */

#define SERVICE_NAME "run_init"	/* the name of this program for PAM */
				  /* The file containing the context to run 
				   * the scripts under.                     */

int authenticate_via_pam(const struct passwd *);

/* authenticate_via_pam()
 *
 * in:     p_passwd_line - struct containing data from our user's line in 
 *                         the passwd file.
 * out:    nothing
 * return: value   condition
 *         -----   ---------
 *           1     PAM thinks that the user authenticated themselves properly
 *           0     otherwise
 *
 * This function uses PAM to authenticate the user running this
 * program.  This is the only function in this program that makes PAM
 * calls.
 *
 */

int authenticate_via_pam(const struct passwd *p_passwd_line)
{

	int result = 0;		/* our result, set to 0 (not authenticated) by default */
	pam_handle_t *pam_handle;	/* opaque handle used by all PAM functions */

	/* This is a jump table of functions for PAM to use when it wants to *
	 * communicate with the user.  We'll be using misc_conv(), which is  *
	 * provided for us via pam_misc.h.                                   */
	struct pam_conv pam_conversation = {
		misc_conv,
		NULL
	};

	/* Make `p_pam_handle' a valid PAM handle so we can use it when *
	 * calling PAM functions.                                       */
	if (PAM_SUCCESS != pam_start(SERVICE_NAME,
				     p_passwd_line->pw_name,
				     &pam_conversation, &pam_handle)) {
		fprintf(stderr, _("failed to initialize PAM\n"));
		exit(-1);
	}

	/* Ask PAM to authenticate the user running this program */
	if (PAM_SUCCESS == pam_authenticate(pam_handle, 0)) {
		result = 1;	/* user authenticated OK! */
	}

	/* If we were successful, call pam_acct_mgmt() to reset the
         * pam_tally failcount.
         */
	if (result && (PAM_SUCCESS != pam_acct_mgmt(pam_handle, 0)) ) {
		fprintf(stderr, _("failed to get account information\n"));
		exit(-1);
	}	

	/* We're done with PAM.  Free `pam_handle'. */
	pam_end(pam_handle, PAM_SUCCESS);

	return (result);

}				/* authenticate_via_pam() */

#else				/* else !USE_PAM */

/************************************************************************
 *
 * All shadow passwd code goes in this section.
 *
 ************************************************************************/

#include <unistd.h>		/* for getuid(), exit(), crypt() */
#include <shadow.h>		/* for shadow passwd functions */
#include <string.h>		/* for strlen(), memset() */

/*
 * crypt() may not be defined in unistd.h; see:
 *   http://man7.org/linux/man-pages/man3/crypt.3.html#NOTES
 */
#if !defined(_XOPEN_CRYPT) || _XOPEN_CRYPT == -1
#include <crypt.h>
#endif

#define PASSWORD_PROMPT _("Password:")	/* prompt for getpass() */

int authenticate_via_shadow_passwd(const struct passwd *);

/* authenticate_via_shadow_passwd()
 *
 * in:     p_passwd_line - struct containing data from our user's line in 
 *                         the passwd file.
 * out:    nothing
 * return: value   condition
 *         -----   ---------
 *           1     user authenticated themselves properly according to the
 *                 shadow passwd file.
 *           0     otherwise
 *
 * This function uses the shadow passwd file to authenticate the user running
 * this program.
 *
 */

int authenticate_via_shadow_passwd(const struct passwd *p_passwd_line)
{

	struct spwd *p_shadow_line;	/* struct derived from shadow passwd file line */
	char *unencrypted_password_s;	/* unencrypted password input by user */
	char *encrypted_password_s;	/* user's password input after being crypt()ed */

	/* Make `p_shadow_line' point to the data from the current user's *
	 * line in the shadow passwd file.                                */
	setspent();		/* Begin access to the shadow passwd file. */
	p_shadow_line = getspnam(p_passwd_line->pw_name);
	endspent();		/* End access to the shadow passwd file. */
	if (!(p_shadow_line)) {
		fprintf(stderr,
			_
			("Cannot find your entry in the shadow passwd file.\n"));
		exit(-1);
	}

	/* Ask user to input unencrypted password */
	if (!(unencrypted_password_s = getpass(PASSWORD_PROMPT))) {
		fprintf(stderr, _("getpass cannot open /dev/tty\n"));
		exit(-1);
	}

	/* Use crypt() to encrypt user's input password.  Clear the *
	 * unencrypted password as soon as we're done, so it is not * 
	 * visible to memory snoopers.                              */
	encrypted_password_s = crypt(unencrypted_password_s,
				     p_shadow_line->sp_pwdp);
	memset(unencrypted_password_s, 0, strlen(unencrypted_password_s));

	/* Return 1 (authenticated) iff the encrypted version of the user's *
	 * input password matches the encrypted password stored in the      *
	 * shadow password file.                                            */
	return (!strcmp(encrypted_password_s, p_shadow_line->sp_pwdp));

}				/* authenticate_via_shadow_passwd() */

#endif				/* if/else USE_PAM */

/*
 * authenticate_user()
 *
 * Authenticate the user.
 *
 * in:		nothing
 * out:		nothing
 * return:	0 When success
 *		-1 When failure
 */
int authenticate_user(void)
{

#define INITLEN 255
	struct passwd *p_passwd_line;	/* struct derived from passwd file line */
	uid_t uid;

	/*
	 * Determine the Linux user identity to re-authenticate.
	 * If supported and set, use the login uid, as this should be more stable.
	 * Otherwise, use the real uid.
	 * The SELinux user identity is no longer used, as Linux users are now
	 * mapped to SELinux users via seusers and the SELinux user identity space
	 * is separate.
	 */
#ifdef USE_AUDIT
	uid = audit_getloginuid();
	if (uid == (uid_t) - 1)
		uid = getuid();
#else
	uid = getuid();
#endif

	p_passwd_line = getpwuid(uid);
	if (!p_passwd_line) {
		fprintf(stderr, "cannot find your entry in the passwd file.\n");
		return (-1);
	}

	printf("Authenticating %s.\n", p_passwd_line->pw_name);

	/* 
	 * Re-authenticate the user running this program.
	 * This is just to help confirm user intent (vs. invocation by
	 * malicious software), not to authorize the operation (which is covered
	 * by policy).  Trusted path mechanism would be preferred.
	 */
#ifdef USE_PAM
	if (!authenticate_via_pam(p_passwd_line)) {
#else				/* !USE_PAM */
	if (!authenticate_via_shadow_passwd(p_passwd_line)) {
#endif				/* if/else USE_PAM */
		fprintf(stderr, _("run_init: incorrect password for %s\n"),
			p_passwd_line->pw_name);
		return (-1);
	}

	/* If we reach here, then we have authenticated the user. */
#ifdef CANTSPELLGDB
	printf("You are authenticated!\n");
#endif

	return 0;

}				/* authenticate_user() */

/*
 * get_init_context()
 *
 * Get the CONTEXT associated with the context for the init scripts.             *
 *
 * in:		nothing
 * out:		The CONTEXT associated with the context.
 * return:	0 on success, -1 on failure.
 */
int get_init_context(char **context)
{

	FILE *fp;
	char buf[255], *bufp;
	int buf_len;
	char context_file[PATH_MAX];
	snprintf(context_file, sizeof(context_file) - 1, "%s/%s",
		 selinux_contexts_path(), CONTEXT_FILE);
	fp = fopen(context_file, "r");
	if (!fp) {
		fprintf(stderr, _("Could not open file %s\n"), context_file);
		return -1;
	}

	while (1) {		/* loop until we find a non-empty line */

		if (!fgets(buf, sizeof buf, fp))
			break;

		buf_len = strlen(buf);
		if (buf[buf_len - 1] == '\n')
			buf[buf_len - 1] = 0;

		bufp = buf;
		while (*bufp && isspace(*bufp))
			bufp++;

		if (*bufp) {
			*context = strdup(bufp);
			if (!(*context))
				goto out;
			fclose(fp);
			return 0;
		}
	}
      out:
	fclose(fp);
	fprintf(stderr, _("No context in file %s\n"), context_file);
	return -1;

}				/* get_init_context() */

/*****************************************************************************
 * main()                                                                    *
 *****************************************************************************/
int main(int argc, char *argv[])
{

	extern char *optarg;	/* used by getopt() for arg strings */
	extern int opterr;	/* controls getopt() error messages */
	char *new_context;	/* context for the init script context  */

#ifdef USE_NLS
	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
#endif

	/* Verify that we are running on a flask-enabled kernel. */
	if (!is_selinux_enabled()) {
		fprintf(stderr,
			_
			("Sorry, run_init may be used only on a SELinux kernel.\n"));
		exit(-1);
	}

	/*
	 * Step 1:  Handle command-line arguments. The first argument is the 
	 * name of the script to run. All other arguments are for the script
	 * itself, and will be passed directly to the script.
	 */

	if (argc < 2) {
		fprintf(stderr, "%s\n", USAGE_STRING);
		exit(-1);
	}

	/*
	 * Step 2:  Authenticate the user.
	 */
	if (authenticate_user() != 0) {
		fprintf(stderr, _("authentication failed.\n"));
		exit(-1);
	}

	/*
	 * Step 3: Get the context for the script to be run in.
	 */
	if (get_init_context(&new_context) == 0) {
#ifdef CANTSPELLGDB
		printf("context is %s\n", new_context);
#endif
	} else {
		exit(-1);
	}

	/*
	 * Step 4: Run the command in the correct context.
	 */

	if (chdir("/")) {
		perror("chdir");
		exit(-1);
	}

	if (setexeccon(new_context) < 0) {
		fprintf(stderr, _("Could not set exec context to %s.\n"),
			new_context);
		exit(-1);
	}
	if (access("/usr/sbin/open_init_pty", X_OK) != 0) {
		if (execvp(argv[1], argv + 1)) {
			perror("execvp");
			exit(-1);
		}
		return 0;
	}
	/*
	 * Do not execvp the command directly from run_init; since it would run
	 * under with a pty under sysadm_devpts_t. Instead, we call open_init_tty,
	 * which transitions us into initrc_t, which then spawns a new
	 * process, that gets a pty with context initrc_devpts_t. Just
	 * execvp or using a exec(1) recycles pty's, and does not open a new
	 * one. 
	 */
	if (execvp("/usr/sbin/open_init_pty", argv)) {
		perror("execvp");
		exit(-1);
	}
	return 0;

}				/* main() */
