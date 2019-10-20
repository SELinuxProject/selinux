/* Authors: Karl MacMillan <kmacmillan@tresys.com>
 *          Joshua Brindle <jbrindle@tresys.com>
 *          Jason Tang <jtang@tresys.com>
 *
 * Copyright (C) 2004-2005 Tresys Technology, LLC
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License as
 *      published by the Free Software Foundation, version 2.
 */

#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <libgen.h>
#include <limits.h>

#include <sepol/cil/cil.h>
#include <semanage/modules.h>

enum client_modes {
	NO_MODE, INSTALL_M, REMOVE_M, EXTRACT_M, CIL_M, HLL_M,
	LIST_M, RELOAD, PRIORITY_M, ENABLE_M, DISABLE_M
};
/* list of modes in which one ought to commit afterwards */
static const int do_commit[] = {
	0, 1, 1, 0, 0, 0,
	0, 0, 0, 1, 1,
};

struct command {
	enum client_modes mode;
	char *arg;
};
static struct command *commands = NULL;
static int num_commands = 0;

/* options given on command line */
static int verbose;
static int reload;
static int no_reload;
static int build;
static int disable_dontaudit;
static int preserve_tunables;
static int ignore_module_cache;
static uint16_t priority;
static int priority_set = 0;

static semanage_handle_t *sh = NULL;
static char *store;
static char *store_root;
int extract_cil = 0;

extern char *optarg;
extern int optind;

static void cleanup(void)
{
	while (--num_commands >= 0) {
		free(commands[num_commands].arg);
	}
	free(commands);
}

/* Signal handlers. */
static void handle_signal(int sig_num)
{
	if (sig_num == SIGINT || sig_num == SIGQUIT || sig_num == SIGTERM) {
		/* catch these signals, and then drop them */
	}
}

static void set_store(char *storename)
{
	/* For now this only supports a store name, later on this 
	 * should support an address for a remote connection */

	if ((store = strdup(storename)) == NULL) {
		fprintf(stderr, "Out of memory!\n");
		goto bad;
	}

	return;

      bad:
	cleanup();
	exit(1);
}

static void set_store_root(char *path)
{
	if ((store_root = strdup(path)) == NULL) {
		fprintf(stderr, "Out of memory!\n");
		goto bad;
	}

	return;

      bad:
	cleanup();
	exit(1);
}

/* Establish signal handlers for the process. */
static void create_signal_handlers(void)
{
	if (signal(SIGINT, handle_signal) == SIG_ERR ||
	    signal(SIGQUIT, handle_signal) == SIG_ERR ||
	    signal(SIGTERM, handle_signal) == SIG_ERR) {
		fprintf(stderr, "Could not set up signal handler.\n");
		exit(255);
	}
}

static void usage(char *progname)
{
	printf("usage:  %s [option]... MODE...\n", progname);
	printf("Manage SELinux policy modules.\n");
	printf("MODES:\n");
	printf("  -R, --reload		    reload policy\n");
	printf("  -B, --build		    build and reload policy\n");
	printf("  -D,--disable_dontaudit    Remove dontaudits from policy\n");
	printf("  -i,--install=MODULE_PKG   install a new module\n");
	printf("  -r,--remove=MODULE_NAME   remove existing module at desired priority\n");
	printf("  -l[KIND],--list-modules[=KIND]  display list of installed modules\n");
	printf("     KIND:  standard  list highest priority, enabled modules\n");
	printf("            full      list all modules\n");
	printf("  -X,--priority=PRIORITY    set priority for following operations (1-999)\n");
	printf("  -e,--enable=MODULE_NAME   enable module\n");
	printf("  -d,--disable=MODULE_NAME  disable module\n");
	printf("  -E,--extract=MODULE_NAME  extract module\n");
	printf("Options:\n");
	printf("  -s,--store	   name of the store to operate on\n");
	printf("  -N,-n,--noreload do not reload policy after commit\n");
	printf("  -h,--help        print this message and quit\n");
	printf("  -v,--verbose     be verbose\n");
	printf("  -P,--preserve_tunables	Preserve tunables in policy\n");
	printf("  -C,--ignore-module-cache	Rebuild CIL modules compiled from HLL files\n");
	printf("  -p,--path        use an alternate path for the policy root\n");
	printf("  -S,--store-path  use an alternate path for the policy store root\n");
	printf("  -c, --cil extract module as cil. This only affects module extraction.\n");
	printf("  -H, --hll extract module as hll. This only affects module extraction.\n");
}

/* Sets the global mode variable to new_mode, but only if no other
 * mode has been given. */
static void set_mode(enum client_modes new_mode, char *arg)
{
	struct command *c;
	char *s;
	if ((c = realloc(commands, sizeof(*c) * (num_commands + 1))) == NULL) {
		fprintf(stderr, "Out of memory!\n");
		cleanup();
		exit(1);
	}
	commands = c;
	commands[num_commands].mode = new_mode;
	commands[num_commands].arg = NULL;
	num_commands++;
	if (arg != NULL) {
		if ((s = strdup(arg)) == NULL) {
			fprintf(stderr, "Out of memory!\n");
			cleanup();
			exit(1);
		}
		commands[num_commands - 1].arg = s;
	}
}

/* Parse command line and set global options. */
static void parse_command_line(int argc, char **argv)
{
	static struct option opts[] = {
		{"store", required_argument, NULL, 's'},
		{"base", required_argument, NULL, 'b'},
		{"help", 0, NULL, 'h'},
		{"install", required_argument, NULL, 'i'},
		{"extract", required_argument, NULL, 'E'},
		{"cil", 0, NULL, 'c'},
		{"hll", 0, NULL, 'H'},
		{"list-modules", optional_argument, NULL, 'l'},
		{"verbose", 0, NULL, 'v'},
		{"remove", required_argument, NULL, 'r'},
		{"upgrade", required_argument, NULL, 'u'},
		{"reload", 0, NULL, 'R'},
		{"noreload", 0, NULL, 'n'},
		{"build", 0, NULL, 'B'},
		{"disable_dontaudit", 0, NULL, 'D'},
		{"preserve_tunables", 0, NULL, 'P'},
		{"ignore-module-cache", 0, NULL, 'C'},
		{"priority", required_argument, NULL, 'X'},
		{"enable", required_argument, NULL, 'e'},
		{"disable", required_argument, NULL, 'd'},
		{"path", required_argument, NULL, 'p'},
		{"store-path", required_argument, NULL, 'S'},
		{NULL, 0, NULL, 0}
	};
	int extract_selected = 0;
	int cil_hll_set = 0;
	int i;
	verbose = 0;
	reload = 0;
	no_reload = 0;
	priority = 400;
	while ((i =
		getopt_long(argc, argv, "s:b:hi:l::vr:u:RnNBDCPX:e:d:p:S:E:cH", opts,
			    NULL)) != -1) {
		switch (i) {
		case 'b':
			fprintf(stderr, "The --base option is deprecated. Use --install instead.\n");
			set_mode(INSTALL_M, optarg);
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
		case 'i':
			set_mode(INSTALL_M, optarg);
			break;
		case 'E':
			set_mode(EXTRACT_M, optarg);
			extract_selected = 1;
			break;
		case 'c':
			set_mode(CIL_M, NULL);
			cil_hll_set = 1;
			break;
		case 'H':
			set_mode(HLL_M, NULL);
			cil_hll_set = 1;
			break;
		case 'l':
			set_mode(LIST_M, optarg);
			break;
		case 'v':
			verbose++;
			break;
		case 'r':
			set_mode(REMOVE_M, optarg);
			break;
		case 'u':
			fprintf(stderr, "The --upgrade option is deprecated. Use --install instead.\n");
			set_mode(INSTALL_M, optarg);
			break;
		case 's':
			set_store(optarg);
			break;
		case 'p':
			semanage_set_root(optarg);
			break;
		case 'S':
			set_store_root(optarg);
			break;
		case 'R':
			reload = 1;
			break;
		case 'n':
			no_reload = 1;
			break;
		case 'N':
			no_reload = 1;
			break;
		case 'B':
			build = 1;
			break;
		case 'D':
			disable_dontaudit = 1;
			break;
		case 'P':
			preserve_tunables = 1;
			break;
		case 'C':
			ignore_module_cache = 1;
			break;
		case 'X':
			set_mode(PRIORITY_M, optarg);
			break;
		case 'e':
			set_mode(ENABLE_M, optarg);
			break;
		case 'd':
			set_mode(DISABLE_M, optarg);
			break;
		case '?':
		default:{
				usage(argv[0]);
				exit(1);
			}
		}
	}
	if ((build || reload) && num_commands) {
		fprintf(stderr,
			"build or reload should not be used with other commands\n");
		usage(argv[0]);
		exit(1);
	}
	if (num_commands == 0 && reload == 0 && build == 0) {
		fprintf(stderr, "At least one mode must be specified.\n");
		usage(argv[0]);
		exit(1);
	}
	if (extract_selected == 0 && cil_hll_set == 1) {
		fprintf(stderr, "--cil and --hll require a module to export with the --extract option.\n");
		usage(argv[0]);
		exit(1);
	}

	if (optind < argc) {
		int mode = commands ? (int) commands[num_commands - 1].mode : -1;
		/* if -i/u/r/E was the last command treat any remaining
		 * arguments as args. Will allow 'semodule -i *.pp' to
		 * work as expected.
		 */

		switch (mode) {
			case INSTALL_M:
			case REMOVE_M:
			case EXTRACT_M:
			case ENABLE_M:
			case DISABLE_M:
				while (optind < argc)
					set_mode(mode, argv[optind++]);
				break;
			default:
				fprintf(stderr, "unknown additional arguments:\n");
				while (optind < argc)
					fprintf(stderr, " %s", argv[optind++]);
				fprintf(stderr, "\n\n");
				usage(argv[0]);
				exit(1);
		}
	}
}

int main(int argc, char *argv[])
{
	int i, commit = 0;
	int result;
	int status = EXIT_FAILURE;
	const char *genhomedirconargv[] = { "genhomedircon", "-B", "-n" };
	create_signal_handlers();
	if (strcmp(basename(argv[0]), "genhomedircon") == 0) {
		argc = 3;
		argv = (char **)genhomedirconargv;
	}
	parse_command_line(argc, argv);

	cil_set_log_level(CIL_ERR + verbose);

	if (build)
		commit = 1;

	sh = semanage_handle_create();
	if (!sh) {
		fprintf(stderr, "%s:  Could not create semanage handle\n",
			argv[0]);
		goto cleanup_nohandle;
	}

	if (store) {
		/* Set the store we want to connect to, before connecting.
		 * this will always set a direct connection now, an additional
		 * option will need to be used later to specify a policy server 
		 * location */
		semanage_select_store(sh, store, SEMANAGE_CON_DIRECT);
	}

	if (store_root) {
		semanage_set_store_root(sh, store_root);
	}

	/* create store if necessary, for bootstrapping */
	semanage_set_create_store(sh, 1);

	if ((result = semanage_connect(sh)) < 0) {
		fprintf(stderr, "%s:  Could not connect to policy handler\n",
			argv[0]);
		goto cleanup;
	}

	if (reload) {
		if ((result = semanage_reload_policy(sh)) < 0) {
			fprintf(stderr, "%s:  Could not reload policy\n",
				argv[0]);
			goto cleanup;
		}
	}

	if (build) {
		if ((result = semanage_begin_transaction(sh)) < 0) {
			fprintf(stderr, "%s:  Could not begin transaction:  %s\n",
				argv[0], errno ? strerror(errno) : "");
			goto cleanup;
		}
	}

	if ((result = semanage_set_default_priority(sh, priority)) != 0) {
		fprintf(stderr,
			"%s: Invalid priority %d (needs to be between 1 and 999)\n",
			argv[0],
			priority);
		goto cleanup;
	}

	for (i = 0; i < num_commands; i++) {
		enum client_modes mode = commands[i].mode;
		char *mode_arg = commands[i].arg;

		switch (mode) {
		case INSTALL_M:{
				if (verbose) {
					printf
					    ("Attempting to install module '%s':\n",
					     mode_arg);
				}
				result =
				    semanage_module_install_file(sh, mode_arg);
				break;
			}
		case EXTRACT_M:{
				semanage_module_info_t *extract_info = NULL;
				semanage_module_key_t *modkey = NULL;
				uint16_t curr_priority;
				void *data = NULL;
				size_t data_len = 0;
				char output_path[PATH_MAX];
				const char *output_name = NULL;
				const char *lang_ext = NULL;
				int rlen;
				FILE *output_fd = NULL;

				result = semanage_module_key_create(sh, &modkey);
				if (result != 0) {
					goto cleanup_extract;
				}

				result = semanage_module_key_set_name(sh, modkey, mode_arg);
				if (result != 0) {
					goto cleanup_extract;
				}

				if (priority_set == 0) {
					result = semanage_module_get_module_info(sh, modkey, &extract_info);
					if (result != 0) {
						goto cleanup_extract;
					}

					semanage_module_info_get_priority(sh, extract_info, &curr_priority);
					printf("Module '%s' does not exist at the default priority '%d'. "
							"Extracting at highest existing priority '%d'.\n", mode_arg, priority, curr_priority);
					priority = curr_priority;
				}

				result  = semanage_module_key_set_priority(sh, modkey, priority);
				if (result != 0) {
					goto cleanup_extract;
				}

				if (verbose) {
					printf
						("Attempting to extract module '%s':\n",
							mode_arg);
				}
				result = semanage_module_extract(sh, modkey, extract_cil, &data, &data_len, &extract_info);
				if (result != 0) {
					goto cleanup_extract;
				}

				if (extract_cil) {
					lang_ext = "cil";
				} else {
					result = semanage_module_info_get_lang_ext(sh, extract_info, &lang_ext);
					if (result != 0) {
						goto cleanup_extract;
					}
				}

				result = semanage_module_info_get_name(sh, extract_info, &output_name);
				if (result != 0) {
					goto cleanup_extract;
				}

				rlen = snprintf(output_path, PATH_MAX, "%s.%s", output_name, lang_ext);
				if (rlen < 0 || rlen >= PATH_MAX) {
					fprintf(stderr, "%s: Failed to generate output path.\n", argv[0]);
					result = -1;
					goto cleanup_extract;
				}

				if (access(output_path, F_OK) == 0) {
					fprintf(stderr, "%s: %s is already extracted with extension %s.\n", argv[0], mode_arg, lang_ext);
					result = -1;
					goto cleanup_extract;
				}

				output_fd = fopen(output_path, "w");
				if (output_fd == NULL) {
					fprintf(stderr, "%s: Unable to open %s\n", argv[0], output_path);
					result = -1;
					goto cleanup_extract;
				}

				if (fwrite(data, 1, data_len, output_fd) < data_len) {
					fprintf(stderr, "%s: Unable to write to %s\n", argv[0], output_path);
					result = -1;
					goto cleanup_extract;
				}
cleanup_extract:
				if (output_fd != NULL) {
					fclose(output_fd);
				}
				if (data_len > 0) {
					munmap(data, data_len);
				}
				semanage_module_info_destroy(sh, extract_info);
				free(extract_info);
				semanage_module_key_destroy(sh, modkey);
				free(modkey);
				break;
			}
		case CIL_M:
				extract_cil = 1;
				break;
		case HLL_M:
				extract_cil = 0;
				break;
		case REMOVE_M:{
				if (verbose) {
					printf
					    ("Attempting to remove module '%s':\n",
					     mode_arg);
				}
				result = semanage_module_remove(sh, mode_arg);
				if ( result == -2 ) { 
					continue;
				}
				break;
			}
		case LIST_M:{
				semanage_module_info_t *modinfos = NULL;
				int modinfos_len = 0;
				semanage_module_info_t *m = NULL;
				int j = 0;

				if (verbose) {
					printf
					    ("Attempting to list active modules:\n");
				}

				if (mode_arg == NULL || strcmp(mode_arg, "standard") == 0) {
					result = semanage_module_list(sh,
								      &modinfos,
								      &modinfos_len);
					if (result < 0) goto cleanup_list;

					if (modinfos_len == 0) {
						printf("No modules.\n");
					}

					const char *name = NULL;

					for (j = 0; j < modinfos_len; j++) {
						m = semanage_module_list_nth(modinfos, j);

						result = semanage_module_info_get_name(sh, m, &name);
						if (result != 0) goto cleanup_list;

						printf("%s\n", name);
					}
				}
				else if (strcmp(mode_arg, "full") == 0) {
					/* get the modules */
					result = semanage_module_list_all(sh,
									  &modinfos,
									  &modinfos_len);
					if (result != 0) goto cleanup_list;

					if (modinfos_len == 0) {
						printf("No modules.\n");
					}

					/* calculate column widths */
					size_t column[4] = { 0, 0, 0, 0 };

					/* fixed width columns */
					column[0] = sizeof("000") - 1;
					column[3] = sizeof("disabled") - 1;

					/* variable width columns */
					const char *tmp = NULL;
					size_t size;
					for (j = 0; j < modinfos_len; j++) {
						m = semanage_module_list_nth(modinfos, j);

						result = semanage_module_info_get_name(sh, m, &tmp);
						if (result != 0) goto cleanup_list;

						size = strlen(tmp);
						if (size > column[1]) column[1] = size;

						result = semanage_module_info_get_lang_ext(sh, m, &tmp);
						if (result != 0) goto cleanup_list;

						size = strlen(tmp);
						if (size > column[3]) column[3] = size;
					}

					/* print out each module */
					for (j = 0; j < modinfos_len; j++) {
						uint16_t pri = 0;
						const char *name = NULL;
						int enabled = 0;
						const char *lang_ext = NULL;

						m = semanage_module_list_nth(modinfos, j);

						result = semanage_module_info_get_priority(sh, m, &pri);
						if (result != 0) goto cleanup_list;

						result = semanage_module_info_get_name(sh, m, &name);
						if (result != 0) goto cleanup_list;

						result = semanage_module_info_get_enabled(sh, m, &enabled);
						if (result != 0) goto cleanup_list;

						result = semanage_module_info_get_lang_ext(sh, m, &lang_ext);
						if (result != 0) goto cleanup_list;

						printf("%0*u %-*s %-*s %-*s\n",
							(int)column[0], pri,
							(int)column[1], name,
							(int)column[2], lang_ext,
							(int)column[3], enabled ? "" : "disabled");
					}
				}
				else {
					result = -1;
				}

cleanup_list:
				for (j = 0; j < modinfos_len; j++) {
					m = semanage_module_list_nth(modinfos, j);
					semanage_module_info_destroy(sh, m);
				}

				free(modinfos);

				break;
			}
		case PRIORITY_M:{
				char *endptr = NULL;
				priority = (uint16_t)strtoul(mode_arg, &endptr, 10);
				priority_set = 1;

				if ((result = semanage_set_default_priority(sh, priority)) != 0) {
					fprintf(stderr,
						"%s: Invalid priority %d (needs to be between 1 and 999)\n",
						argv[0],
						priority);
					goto cleanup;
				}

				break;
			}
		case ENABLE_M:{
				if (verbose) {
					printf
					    ("Attempting to enable module '%s':\n",
					     mode_arg);
				}

				semanage_module_key_t *modkey = NULL;

				result = semanage_module_key_create(sh, &modkey);
				if (result != 0) goto cleanup_enable;

				result = semanage_module_key_set_name(sh, modkey, mode_arg);
				if (result != 0) goto cleanup_enable;

				result = semanage_module_set_enabled(sh, modkey, 1);
				if (result != 0) goto cleanup_enable;

cleanup_enable:
				semanage_module_key_destroy(sh, modkey);
				free(modkey);

				break;
			}
		case DISABLE_M:{
				if (verbose) {
					printf
					    ("Attempting to disable module '%s':\n",
					     mode_arg);
				}

				semanage_module_key_t *modkey = NULL;

				result = semanage_module_key_create(sh, &modkey);
				if (result != 0) goto cleanup_disable;

				result = semanage_module_key_set_name(sh, modkey, mode_arg);
				if (result != 0) goto cleanup_disable;

				result = semanage_module_set_enabled(sh, modkey, 0);
				if (result != 0) goto cleanup_disable;

cleanup_disable:
				semanage_module_key_destroy(sh, modkey);
				free(modkey);

				break;
			}
		default:{
				fprintf(stderr,
					"%s:  Unknown mode specified.\n",
					argv[0]);
				usage(argv[0]);
				goto cleanup;
			}
		}
		commit += do_commit[mode];
		if (result < 0) {
			fprintf(stderr, "%s:  Failed on %s!\n", argv[0],
				mode_arg ? : "list");
			goto cleanup;
		} else if (verbose) {
			printf("Ok: return value of %d.\n", result);
		}
	}

	if (commit) {
		if (verbose)
			printf("Committing changes:\n");
		if (no_reload)
			semanage_set_reload(sh, 0);
		if (build)
			semanage_set_rebuild(sh, 1);
		if (disable_dontaudit)
			semanage_set_disable_dontaudit(sh, 1);
		else if (build)
			semanage_set_disable_dontaudit(sh, 0);
		if (preserve_tunables)
			semanage_set_preserve_tunables(sh, 1);
		if (ignore_module_cache)
			semanage_set_ignore_module_cache(sh, 1);

		result = semanage_commit(sh);
	}

	if (result < 0) {
		fprintf(stderr, "%s:  Failed!\n", argv[0]);
		goto cleanup;
	} else if (commit && verbose) {
		printf("Ok: transaction number %d.\n", result);
	}

	if (semanage_disconnect(sh) < 0) {
		fprintf(stderr, "%s:  Error disconnecting\n", argv[0]);
		goto cleanup;
	}
	status = EXIT_SUCCESS;

      cleanup:
	if (semanage_is_connected(sh)) {
		if (semanage_disconnect(sh) < 0) {
			fprintf(stderr, "%s:  Error disconnecting\n", argv[0]);
		}
	}
	semanage_handle_destroy(sh);

      cleanup_nohandle:
	cleanup();
	exit(status);
}
