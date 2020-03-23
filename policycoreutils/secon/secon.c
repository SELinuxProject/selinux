
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include <string.h>

#define xstreq(x, y) !strcmp(x, y)

#include <err.h>

#include <getopt.h>
#include <sys/types.h>
#include <unistd.h>
#include <selinux/selinux.h>
#include <selinux/context.h>

#define TRUE  1
#define FALSE 0

#define SECON_CONF_PROG_NAME "secon"	/* default program name */
#define SECON_OPTS_SM "hVurtscmPRCfLp"	/* small options available, print */
#define SECON_OPTS_GO "hVurtlscmPRCf:L:p:"	/* small options available, getopt */

#define OPTS_FROM_ARG      0
#define OPTS_FROM_FILE     1
#define OPTS_FROM_LINK     2
#define OPTS_FROM_STDIN    3
#define OPTS_FROM_CUR      4
#define OPTS_FROM_CUREXE   5
#define OPTS_FROM_CURFS    6
#define OPTS_FROM_CURKEY   7
#define OPTS_FROM_PROC     8
#define OPTS_FROM_PROCEXE  9
#define OPTS_FROM_PROCFS   10
#define OPTS_FROM_PROCKEY  11

struct context_color_t {
	unsigned int valid;

	char *user_fg;
	char *user_bg;
	char *role_fg;
	char *role_bg;
	char *type_fg;
	char *type_bg;
	char *range_fg;
	char *range_bg;
};

struct {
	unsigned int disp_user:1;
	unsigned int disp_role:1;
	unsigned int disp_type:1;
	unsigned int disp_sen:1;
	unsigned int disp_clr:1;
	unsigned int disp_mlsr:1;

	unsigned int disp_raw:1;
	unsigned int disp_color:1;

	unsigned int disp_prompt:1;	/* no return, use : to sep */

	unsigned int from_type:8;	/* 16 bits, uses 4 bits */

	union {
		pid_t pid;
		const char *file;
		const char *link;
		const char *arg;
	} f;
} opts[1] = { {
		FALSE, FALSE, FALSE, FALSE, FALSE, FALSE,
		    FALSE, FALSE, FALSE, OPTS_FROM_ARG, {0} } };

static __attribute__((__noreturn__)) void usage(const char *name, int exit_code)
{
	fprintf(exit_code ? stderr : stdout,
		"  Usage: %s [-%s] [ context | - ]\n"
		"          --help          -h            Show this message.\n"
		"          --version       -V            Show the version.\n"
		"          --prompt        -P            Output in a format good for a prompt.\n"
		"          --user          -u            Show the user of the context.\n"
		"          --role          -r            Show the role of the context.\n"
		"          --type          -t            Show the type of the context.\n"
		"          --sensitivity   -s            Show the sensitivity level of the context.\n"
		"          --clearance     -c            Show the clearance level of the context.\n"
		"          --mls-range     -m            Show the sensitivity to clearance range of \n"
		"                                        the context.\n"
		"          --raw           -R            Show the context in \"raw\" format.\n"
		"          --color         -C            Output using ANSI color codes (requires -P).\n"
		"          --current,      --self        Get the context for the current process.\n"
		"          --current-exec, --self-exec   Get the exec context for the current process.\n"
		"          --current-fs,   --self-fs     Get the fs context for the current process.\n"
		"          --current-key,  --self-key    Get the key context for the current process.\n"
		"          --parent                      Get the context for the parent process.\n"
		"          --parent-exec                 Get the exec context for the parent process.\n"
		"          --parent-fs                   Get the fs context for the parent process.\n"
		"          --parent-key                  Get the key context for the parent process.\n"
		"          --pid           -p <arg>      Use the context from the specified pid.\n"
		"          --pid-exec      <arg>         Use the exec context from the specified pid.\n"
		"          --pid-fs        <arg>         Use the fs context from the specified pid.\n"
		"          --pid-key       <arg>         Use the key context from the specified pid.\n"
		"          --file          -f <arg>      Use the context from the specified file.\n"
		"          --link          -L <arg>      Use the context from the specified link.\n",
		name, SECON_OPTS_SM);

	exit(exit_code);
}

static const char *opt_program_name(const char *argv0, const char *def)
{
	if (argv0) {
		if ((def = strrchr(argv0, '/')))
			++def;
		else
			def = argv0;

		/* hack for libtool */
		if ((strlen(def) > strlen("lt-"))
		    && !memcmp("lt-", def, strlen("lt-")))
			def += 3;
	}

	return (def);
}

static int disp_num(void)
{
	int num = 0;

	num += opts->disp_user;
	num += opts->disp_role;
	num += opts->disp_type;
	num += opts->disp_sen;
	num += opts->disp_clr;
	num += opts->disp_mlsr;

	return (num);
}

static int disp_none(void)
{
	return (!disp_num());
}

static int disp_multi(void)
{
	return (disp_num() > 1);
}

static void cmd_line(int argc, char *argv[])
{
	int optchar = 0;
	const char *program_name = NULL;
	struct option long_options[] = {
		{"help", no_argument, NULL, 'h'},
		{"version", no_argument, NULL, 'V'},

		{"prompt", no_argument, NULL, 'P'},

		{"user", no_argument, NULL, 'u'},
		{"role", no_argument, NULL, 'r'},
		{"type", no_argument, NULL, 't'},
		{"level", no_argument, NULL, 'l'},	/* compat. */
		{"sensitivity", no_argument, NULL, 's'},
		{"range", no_argument, NULL, 'm'},
		{"clearance", no_argument, NULL, 'c'},
		{"mls-range", no_argument, NULL, 'm'},

		{"raw", no_argument, NULL, 'R'},
		{"color", no_argument, NULL, 'C'},

		{"current", no_argument, NULL, 1},
		{"self", no_argument, NULL, 1},
		{"current-exec", no_argument, NULL, 2},
		{"self-exec", no_argument, NULL, 2},
		{"current-fs", no_argument, NULL, 3},
		{"self-fs", no_argument, NULL, 3},
		{"current-key", no_argument, NULL, 4},
		{"self-key", no_argument, NULL, 4},

		{"parent", no_argument, NULL, 5},
		{"parent-exec", no_argument, NULL, 6},
		{"parent-fs", no_argument, NULL, 7},
		{"parent-key", no_argument, NULL, 8},

		{"file", required_argument, NULL, 'f'},
		{"link", required_argument, NULL, 'L'},
		{"pid", required_argument, NULL, 'p'},
		{"pid-exec", required_argument, NULL, 9},
		{"pid-fs", required_argument, NULL, 10},
		{"pid-key", required_argument, NULL, 11},

		{NULL, 0, NULL, 0}
	};
	int done = FALSE;

	program_name = opt_program_name(argv[0], SECON_CONF_PROG_NAME);

	while ((optchar = getopt_long(argc, argv, SECON_OPTS_GO,
				      long_options, NULL)) != -1) {
		switch (optchar) {
		case '?':
			usage(program_name, EXIT_FAILURE);
		case 'h':
			usage(program_name, EXIT_SUCCESS);
		case 'V':
			fprintf(stdout,
				" %s version %s.\n", program_name, VERSION);
			exit(EXIT_SUCCESS);

		case 'u':
			done = TRUE;
			opts->disp_user = !opts->disp_user;
			break;
		case 'r':
			done = TRUE;
			opts->disp_role = !opts->disp_role;
			break;
		case 't':
			done = TRUE;
			opts->disp_type = !opts->disp_type;
			break;
		case 'l':
			done = TRUE;
			opts->disp_sen = !opts->disp_sen;
			break;
		case 's':
			done = TRUE;
			opts->disp_sen = !opts->disp_sen;
			break;
		case 'c':
			done = TRUE;
			opts->disp_clr = !opts->disp_clr;
			break;
		case 'm':
			done = TRUE;
			opts->disp_mlsr = !opts->disp_mlsr;
			break;

		case 'P':
			opts->disp_prompt = !opts->disp_prompt;
			break;

		case 'R':
			opts->disp_raw = !opts->disp_raw;
			break;
		case 'C':
			opts->disp_color = !opts->disp_color;
			break;
		case 1:
			opts->from_type = OPTS_FROM_CUR;
			break;
		case 2:
			opts->from_type = OPTS_FROM_CUREXE;
			break;
		case 3:
			opts->from_type = OPTS_FROM_CURFS;
			break;
		case 4:
			opts->from_type = OPTS_FROM_CURKEY;
			break;

		case 5:
			opts->from_type = OPTS_FROM_PROC;
			opts->f.pid = getppid();
			break;
		case 6:
			opts->from_type = OPTS_FROM_PROCEXE;
			opts->f.pid = getppid();
			break;
		case 7:
			opts->from_type = OPTS_FROM_PROCFS;
			opts->f.pid = getppid();
			break;
		case 8:
			opts->from_type = OPTS_FROM_PROCKEY;
			opts->f.pid = getppid();
			break;

		case 'f':
			opts->from_type = OPTS_FROM_FILE;
			opts->f.file = optarg;
			break;
		case 'L':
			opts->from_type = OPTS_FROM_LINK;
			opts->f.link = optarg;
			break;
		case 'p':
			opts->from_type = OPTS_FROM_PROC;
			opts->f.pid = atoi(optarg);
			break;
		case 9:
			opts->from_type = OPTS_FROM_PROCEXE;
			opts->f.pid = atoi(optarg);
			break;
		case 10:
			opts->from_type = OPTS_FROM_PROCFS;
			opts->f.pid = atoi(optarg);
			break;
		case 11:
			opts->from_type = OPTS_FROM_PROCKEY;
			opts->f.pid = atoi(optarg);
			break;

		default:
			assert(FALSE);
		}
	}

	if (!done) {		/* default, if nothing specified */
		opts->disp_user = TRUE;
		opts->disp_role = TRUE;
		opts->disp_type = TRUE;
		if (!opts->disp_prompt) {	/* when displaying prompt, just output "normal" by default */
			opts->disp_sen = TRUE;
			opts->disp_clr = TRUE;
		}
		opts->disp_mlsr = TRUE;
	}

	if (disp_none())
		err(EXIT_FAILURE, " Nothing to display");

	argc -= optind;
	argv += optind;

	if (!argc && (opts->from_type == OPTS_FROM_ARG)
	    && !isatty(STDIN_FILENO))
		opts->from_type = OPTS_FROM_STDIN;
	if (!argc && (opts->from_type == OPTS_FROM_ARG))
		opts->from_type = OPTS_FROM_CUR;

	if (opts->from_type == OPTS_FROM_ARG) {
		opts->f.arg = argv[0];

		if (xstreq(argv[0], "-"))
			opts->from_type = OPTS_FROM_STDIN;
	} else if (!is_selinux_enabled())
		errx(EXIT_FAILURE, "SELinux is not enabled");
}

static int my_getXcon_raw(pid_t pid, char  **con, const char *val)
{
	char buf[4096];
	FILE *fp = NULL;
	const char *ptr = NULL;

	snprintf(buf, sizeof(buf), "%s/%ld/attr/%s", "/proc", (long int)pid,
		 val);

	if (!(fp = fopen(buf, "rb")))
		return (-1);

	ptr = fgets(buf, sizeof(buf), fp);

	fclose(fp);

	*con = NULL;
	if (ptr) {		/* return *con = NULL, when proc file is empty */
		char *tmp = strchr(ptr, '\n');

		if (tmp)
			*tmp = 0;

		if (*ptr && !(*con = strdup(ptr)))
			return (-1);
	}

	return (0);
}

static int my_getpidexeccon_raw(pid_t pid, char **con)
{
	return (my_getXcon_raw(pid, con, "exec"));
}
static int my_getpidfscreatecon_raw(pid_t pid, char **con)
{
	return (my_getXcon_raw(pid, con, "fscreate"));
}
static int my_getpidkeycreatecon_raw(pid_t pid, char **con)
{
	return (my_getXcon_raw(pid, con, "keycreate"));
}

static char *get_scon(void)
{
	static char dummy_NIL[1] = "";
	char *con = NULL, *con_tmp;
	int ret = -1;

	switch (opts->from_type) {
	case OPTS_FROM_ARG:
		if (!(con_tmp = strdup(opts->f.arg)))
			err(EXIT_FAILURE,
			    " Couldn't allocate security context");
		if (selinux_trans_to_raw_context(con_tmp, &con) < 0)
			err(EXIT_FAILURE,
			    " Couldn't translate security context");
		freecon(con_tmp);
		break;

	case OPTS_FROM_STDIN:
		{
			char buf[4096] = "";
			char *ptr = buf;

			while (!*ptr) {
				if (!(ptr = fgets(buf, sizeof(buf), stdin)))
					err(EXIT_FAILURE,
					    " Couldn't read security context");

				ptr += strspn(ptr, " \n\t");
				ptr[strcspn(ptr, " \n\t")] = 0;
			}

			if (!(con_tmp = strdup(ptr)))
				err(EXIT_FAILURE,
				    " Couldn't allocate security context");
			if (selinux_trans_to_raw_context(con_tmp, &con) < 0)
				err(EXIT_FAILURE,
				    " Couldn't translate security context");
			freecon(con_tmp);
			break;
		}

	case OPTS_FROM_CUR:
		ret = getcon_raw(&con);

		if (ret == -1)
			err(EXIT_FAILURE,
			    " Couldn't get current security context");
		break;
	case OPTS_FROM_CUREXE:
		ret = getexeccon_raw(&con);

		if (ret == -1)
			err(EXIT_FAILURE,
			    " Couldn't get current exec security context");

		if (!con)
			con = strdup(dummy_NIL);
		break;
	case OPTS_FROM_CURFS:
		ret = getfscreatecon_raw(&con);

		if (ret == -1)
			err(EXIT_FAILURE,
			    " Couldn't get current fs security context");

		if (!con)
			con = strdup(dummy_NIL);
		break;
	case OPTS_FROM_CURKEY:
		ret = getkeycreatecon_raw(&con);

		if (ret == -1)
			err(EXIT_FAILURE,
			    " Couldn't get current key security context");

		if (!con)
			con = strdup(dummy_NIL);
		break;

	case OPTS_FROM_PROC:
		ret = getpidcon_raw(opts->f.pid, &con);

		if (ret == -1)
			err(EXIT_FAILURE,
			    " Couldn't get security context for pid %lu",
			    (unsigned long)opts->f.pid);
		break;
	case OPTS_FROM_PROCEXE:
		ret = my_getpidexeccon_raw(opts->f.pid, &con);

		if (ret == -1)
			err(EXIT_FAILURE,
			    " Couldn't get security context for pid %lu",
			    (unsigned long)opts->f.pid);

		if (!con)
			con = strdup(dummy_NIL);
		break;
	case OPTS_FROM_PROCFS:
		ret = my_getpidfscreatecon_raw(opts->f.pid, &con);

		if (ret == -1)
			err(EXIT_FAILURE,
			    " Couldn't get security context for pid %lu",
			    (unsigned long)opts->f.pid);

		if (!con)
			con = strdup(dummy_NIL);
		/* disabled -- override with normal context ...
		   {
		   opts->from_type = OPTS_FROM_PROC;
		   return (get_scon());
		   } */
		break;
	case OPTS_FROM_PROCKEY:
		ret = my_getpidkeycreatecon_raw(opts->f.pid, &con);

		if (ret == -1)
			err(EXIT_FAILURE,
			    " Couldn't get security context for pid %lu",
			    (unsigned long)opts->f.pid);

		if (!con)
			con = strdup(dummy_NIL);
		break;

	case OPTS_FROM_FILE:
		ret = getfilecon_raw(opts->f.file, &con);

		if (ret == -1)
			err(EXIT_FAILURE,
			    " Couldn't get security context for file %s",
			    opts->f.file);
		break;

	case OPTS_FROM_LINK:
		ret = lgetfilecon_raw(opts->f.link, &con);

		if (ret == -1)
			err(EXIT_FAILURE,
			    " Couldn't get security context for symlink %s",
			    opts->f.link);
		break;

	default:
		assert(FALSE);
	}

	return (con);
}

static unsigned int disp__color_to_ansi(const char *color_str)
{
	int val = 30;

	/* NOTE: ansi black is 30 for foreground colors */

	/* red */
	if (strncasecmp(&color_str[1], "7f", 2) >= 0)
		val += 1;
	/* green */
	if (strncasecmp(&color_str[3], "7f", 2) >= 0)
		val += 2;
	/* blue */
	if (strncasecmp(&color_str[5], "7f", 2) >= 0)
		val += 4;

	return val;
}

static char *disp__con_color_ansi(const char *name,
				  struct context_color_t *color)
{
	unsigned int fg, bg;
	char *ansi;
	int ansi_len = strlen("\e[99;99m") + 1;

	/* NOTE: ansi background codes are the same as foreground codes +10 */

	if (xstreq("user", name)) {
		fg = disp__color_to_ansi(color->user_fg);
		bg = disp__color_to_ansi(color->user_bg) + 10;
	} else if (xstreq("role", name)) {
		fg = disp__color_to_ansi(color->role_fg);
		bg = disp__color_to_ansi(color->role_bg) + 10;
	} else if (xstreq("type", name)) {
		fg = disp__color_to_ansi(color->type_fg);
		bg = disp__color_to_ansi(color->type_bg) + 10;
	} else if (xstreq("sensitivity", name) ||
		   xstreq("clearance", name) ||
		   xstreq("mls-range", name)) {
		fg = disp__color_to_ansi(color->range_fg);
		bg = disp__color_to_ansi(color->range_bg) + 10;
	} else
		err(EXIT_FAILURE, " No color information for context field");

	if (!(ansi = malloc(ansi_len)))
		err(EXIT_FAILURE, " Unable to allocate memory");
	if (snprintf(ansi, ansi_len, "\e[%d;%dm", fg, bg) > ansi_len)
		err(EXIT_FAILURE, " Unable to convert colors to ANSI codes");

	return ansi;
}

static void disp__con_val(const char *name, const char *val,
			  struct context_color_t *color)
{
	static int done = FALSE;

	assert(name);
	assert(color);

	if (!val)
		val = "";	/* targeted has no "level" etc.,
				   any errors should happen at context_new() time */

	if (opts->disp_prompt) {
		if (xstreq("mls-range", name) && !*val)
			return;	/* skip, mls-range if it's empty */

		if (opts->disp_color && color->valid) {
			char *ansi = disp__con_color_ansi(name, color);
			fprintf(stdout, "%s", ansi);
			free(ansi);
		}
		fprintf(stdout, "%s%s", done ? ":" : "", val);
		if (opts->disp_color && color->valid)
			fprintf(stdout, "\e[0m");
	} else if (disp_multi())
		fprintf(stdout, "%s: %s\n", name, val);
	else
		fprintf(stdout, "%s\n", val);

	done = TRUE;
}

static void disp_con(const char *scon_raw)
{
	char *scon_trans;
	const char *scon;
	context_t con = NULL;
	char *color_str = NULL;
	struct context_color_t color = { .valid = 0 };

	selinux_raw_to_trans_context(scon_raw, &scon_trans);
	if (opts->disp_raw)
		scon = scon_raw;
	else
		scon = scon_trans;

	if (!*scon) {		/* --self-exec and --self-fs etc. */
		if (opts->disp_user)
			disp__con_val("user", NULL, &color);
		if (opts->disp_role)
			disp__con_val("role", NULL, &color);
		if (opts->disp_type)
			disp__con_val("type", NULL, &color);
		if (opts->disp_sen)
			disp__con_val("sensitivity", NULL, &color);
		if (opts->disp_clr)
			disp__con_val("clearance", NULL, &color);
		if (opts->disp_mlsr)
			disp__con_val("mls-range", NULL, &color);
		freecon(scon_trans);
		return;
	}

	if (opts->disp_color) {
		if (selinux_raw_context_to_color(scon_raw, &color_str) < 0)
			errx(EXIT_FAILURE, "Couldn't determine colors for: %s",
			     scon);

		color.user_fg = strtok(color_str, " ");
		if (!color.user_fg)
			errx(EXIT_FAILURE, "Invalid color string");
		color.user_bg = strtok(NULL, " ");
		if (!color.user_bg)
			errx(EXIT_FAILURE, "Invalid color string");

		color.role_fg = strtok(NULL, " ");
		if (!color.role_fg)
			errx(EXIT_FAILURE, "Invalid color string");
		color.role_bg = strtok(NULL, " ");
		if (!color.role_bg)
			errx(EXIT_FAILURE, "Invalid color string");

		color.type_fg = strtok(NULL, " ");
		if (!color.type_fg)
			errx(EXIT_FAILURE, "Invalid color string");
		color.type_bg = strtok(NULL, " ");
		if (!color.type_bg)
			errx(EXIT_FAILURE, "Invalid color string");

		color.range_fg = strtok(NULL, " ");
		if (!color.range_fg)
			errx(EXIT_FAILURE, "Invalid color string");
		color.range_bg = strtok(NULL, " ");

		color.valid = 1;
	};

	if (!(con = context_new(scon)))
		errx(EXIT_FAILURE, "Couldn't create context from: %s", scon);

	if (opts->disp_user) {
		disp__con_val("user", context_user_get(con), &color);
	}
	if (opts->disp_role) {
		disp__con_val("role", context_role_get(con), &color);
	}
	if (opts->disp_type) {
		disp__con_val("type", context_type_get(con), &color);
	}
	if (opts->disp_sen) {
		const char *val = NULL;
		char *tmp = NULL;

		val = context_range_get(con);
		if (!val)
			val = "";	/* targeted has no "level" etc.,
					   any errors should happen at context_new() time */

		tmp = strdup(val);
		if (!tmp)
			errx(EXIT_FAILURE, "Couldn't create context from: %s",
			     scon);
		if (strchr(tmp, '-'))
			*strchr(tmp, '-') = 0;

		disp__con_val("sensitivity", tmp, &color);

		free(tmp);
	}
	if (opts->disp_clr) {
		const char *val = NULL;
		char *tmp = NULL;

		val = context_range_get(con);
		if (!val)
			val = "";	/* targeted has no "level" etc.,
					   any errors should happen at context_new() time */

		tmp = strdup(val);
		if (!tmp)
			errx(EXIT_FAILURE, "Couldn't create context from: %s",
			     scon);
		if (strchr(tmp, '-'))
			disp__con_val("clearance", strchr(tmp, '-') + 1, &color);
		else
			disp__con_val("clearance", tmp, &color);

		free(tmp);
	}

	if (opts->disp_mlsr)
		disp__con_val("mls-range", context_range_get(con), &color);

	context_free(con);
	freecon(scon_trans);
	if (color_str)
		free(color_str);
}

int main(int argc, char *argv[])
{
	char *scon_raw = NULL;

	cmd_line(argc, argv);

	scon_raw = get_scon();

	disp_con(scon_raw);

	freecon(scon_raw);

	exit(EXIT_SUCCESS);
}
