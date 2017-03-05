#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include <getopt.h>
#include <pwd.h>
#include <selinux/selinux.h>
#include <semanage/handle.h>
#include <semanage/debug.h>
#include <semanage/booleans_policy.h>
#include <semanage/booleans_local.h>
#include <semanage/booleans_active.h>
#include <semanage/boolean_record.h>
#include <errno.h>

int permanent = 0;
int reload = 1;
int verbose = 0;

int setbool(char **list, size_t start, size_t end);

static __attribute__((__noreturn__)) void usage(void)
{
	fputs
	    ("\nUsage:  setsebool [ -NPV ] boolean value | bool1=val1 bool2=val2...\n\n",
	     stderr);
	exit(1);
}

int main(int argc, char **argv)
{
	size_t rc;
	int clflag;		/* holds codes for command line flags */
	if (argc < 2)
		usage();

	if (is_selinux_enabled() <= 0) {
		fputs("setsebool:  SELinux is disabled.\n", stderr);
		return 1;
	}

	while (1) {
		clflag = getopt(argc, argv, "PNV");
		if (clflag == -1)
			break;

		switch (clflag) {
		case 'P':
			permanent = 1;
			break;
		case 'N':
			reload = 0;
			break;
		case 'V':
			verbose = 1;
			break;
		default:
			usage();
			break;
		}
	}

	if (argc - optind < 1) {
		fprintf(stderr, "Error: boolean name required\n");
		usage();
	}

	/* Check to see which way we are being called. If a '=' is passed,
	   we'll enforce the list syntax. If not we'll enforce the original
	   syntax for backward compatibility. */
	if (strchr(argv[optind], '=') == 0) {
		int len;
		char *bool_list[1];

		if ((argc - optind) != 2)
			usage();

		/* Add 1 for the '=' */
		len = strlen(argv[optind]) + strlen(argv[optind + 1]) + 2;
		bool_list[0] = (char *)malloc(len);
		if (bool_list[0] == 0) {
			fputs("Out of memory - aborting\n", stderr);
			return 1;
		}
		snprintf(bool_list[0], len, "%s=%s", argv[optind],
			 argv[optind + 1]);
		rc = setbool(bool_list, 0, 1);
		free(bool_list[0]);
	} else
		rc = setbool(argv, optind, argc);

	return rc;
}

/* Apply temporal boolean changes to policy via libselinux */
static int selinux_set_boolean_list(size_t boolcnt,
				    SELboolean * boollist)
{

	if (security_set_boolean_list(boolcnt, boollist, 0)) {
		if (errno == ENOENT)
			fprintf(stderr, "Could not change active booleans: "
				"Invalid boolean\n");
		else if (errno) {
			if (getuid() == 0) {
				perror("Could not change active booleans");
			} else {
				perror("Could not change active booleans. Please try as root");
			}
		}

		return -1;
	}

	return 0;
}

/* Apply permanent boolean changes to policy via libsemanage */
static int semanage_set_boolean_list(size_t boolcnt,
				     SELboolean * boollist)
{

	size_t j;
	semanage_handle_t *handle = NULL;
	semanage_bool_t *boolean = NULL;
	semanage_bool_key_t *bool_key = NULL;
	int managed;
	int result;

	handle = semanage_handle_create();
	if (handle == NULL) {
		fprintf(stderr, "Could not create semanage library handle\n");
		goto err;
	}

	if (! verbose) {
		semanage_msg_set_callback(handle,NULL, NULL);
	}

	managed = semanage_is_managed(handle);
	if (managed < 0) {
		fprintf(stderr,
			"Error when checking whether policy is managed\n");
		goto err;

	} else if (managed == 0) {
		if (getuid() == 0) {
			fprintf(stderr,
				"Cannot set persistent booleans without managed policy.\n");
		} else {
			fprintf(stderr,
				"Cannot set persistent booleans, please try as root.\n");
		}
		goto err;
	}

	if (semanage_connect(handle) < 0)
		goto err;

	if (semanage_begin_transaction(handle) < 0)
		goto err;

	for (j = 0; j < boolcnt; j++) {

		if (semanage_bool_create(handle, &boolean) < 0)
			goto err;

		if (semanage_bool_set_name(handle, boolean, boollist[j].name) <
		    0)
			goto err;

		semanage_bool_set_value(boolean, boollist[j].value);

		if (semanage_bool_key_extract(handle, boolean, &bool_key) < 0)
			goto err;

		semanage_bool_exists(handle, bool_key, &result);
		if ( !result ) {
			semanage_bool_exists_local(handle, bool_key, &result);
			if ( !result ) {
				fprintf(stderr, "Boolean %s is not defined\n", boollist[j].name);
				goto err;
			}
		}

		if (semanage_bool_modify_local(handle, bool_key,
						  boolean) < 0)
			goto err;

		if (semanage_bool_set_active(handle, bool_key, boolean) < 0) {
			fprintf(stderr, "Failed to change boolean %s: %m\n",
				boollist[j].name);
			goto err;
		}
		semanage_bool_key_free(bool_key);
		semanage_bool_free(boolean);
		bool_key = NULL;
		boolean = NULL;
	}

	semanage_set_reload(handle, reload);
	if (semanage_commit(handle) < 0)
		goto err;

	semanage_disconnect(handle);
	semanage_handle_destroy(handle);
	return 0;

      err:
	semanage_bool_key_free(bool_key);
	semanage_bool_free(boolean);
	semanage_handle_destroy(handle);
	return -1;
}

/* Given an array of strings in the form "boolname=value", a start index,
   and a finish index...walk the list and set the bool. */
int setbool(char **list, size_t start, size_t end)
{
	char *name, *value_ptr;
	int j = 0, value;
	size_t i = start;
	size_t boolcnt = end - start;
	struct passwd *pwd;
	SELboolean *vallist = calloc(boolcnt, sizeof(SELboolean));
	if (!vallist)
		goto omem;

	while (i < end) {
		name = list[i];
		value_ptr = strchr(list[i], '=');
		if (value_ptr == 0) {
			fprintf(stderr,
				"setsebool: '=' not found in boolean expression %s\n",
				list[i]);
			goto err;
		}
		*value_ptr = 0;
		value_ptr++;
		if (strcmp(value_ptr, "1") == 0 ||
		    strcasecmp(value_ptr, "true") == 0 ||
		    strcasecmp(value_ptr, "on") == 0)
			value = 1;
		else if (strcmp(value_ptr, "0") == 0 ||
			 strcasecmp(value_ptr, "false") == 0 ||
			 strcasecmp(value_ptr, "off") == 0)
			value = 0;
		else {
			fprintf(stderr, "setsebool: illegal value "
				"%s for boolean %s\n", value_ptr, name);
			goto err;
		}

		vallist[j].value = value;
		vallist[j].name = strdup(name);
		if (!vallist[j].name)
			goto omem;
		i++;
		j++;

		/* Now put it back */
		value_ptr--;
		*value_ptr = '=';
	}

	if (permanent) {
		if (semanage_set_boolean_list(boolcnt, vallist) < 0)
			goto err;
	} else {
		if (selinux_set_boolean_list(boolcnt, vallist) < 0)
			goto err;
	}

	/* Now log what was done */
	pwd = getpwuid(getuid());
	i = start;
	while (i < end) {
		name = list[i];
		value_ptr = strchr(name, '=');
		*value_ptr = 0;
		value_ptr++;
		if (pwd && pwd->pw_name)
			syslog(LOG_NOTICE,
			       "The %s policy boolean was changed to %s by %s",
			       name, value_ptr, pwd->pw_name);
		else
			syslog(LOG_NOTICE,
			       "The %s policy boolean was changed to %s by uid:%d",
			       name, value_ptr, getuid());
		i++;
	}

	for (i = 0; i < boolcnt; i++)
		free(vallist[i].name);
	free(vallist);
	return 0;

      omem:
	fprintf(stderr, "setsebool: out of memory");

      err:
	if (vallist) {
		for (i = 0; i < boolcnt; i++)
			free(vallist[i].name);
		free(vallist);
	}
	return -1;
}
