/*
 * Copyright (C) 2014  Tresys Technology, LLC
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sepol/module.h>
#include <sepol/module_to_cil.h>
#include <sepol/policydb/module.h>

char *progname;

__attribute__ ((format(printf, 1, 2)))
static void log_err(const char *fmt, ...)
{
	va_list argptr;
	va_start(argptr, fmt);
	if (vfprintf(stderr, fmt, argptr) < 0) {
		_exit(EXIT_FAILURE);
	}
	va_end(argptr);
	if (fprintf(stderr, "\n") < 0) {
		_exit(EXIT_FAILURE);
	}
}

static __attribute__((__noreturn__)) void usage(int err)
{
	fprintf(stderr, "Usage: %s [OPTIONS] [IN_FILE [OUT_FILE]]\n", progname);
	fprintf(stderr, "\n");
	fprintf(stderr, "Read an SELinux policy package (.pp) and output the equivilent CIL.\n");
	fprintf(stderr, "If IN_FILE is not provided or is -, read SELinux policy package from\n");
	fprintf(stderr, "standard input. If OUT_FILE is not provided or is -, output CIL to\n");
	fprintf(stderr, "standard output.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -h, --help      print this message and exit\n");
	exit(err);
}

int main(int argc, char **argv)
{
	int rc = -1;
	int opt;
	static struct option long_opts[] = {
		{ "help", 0, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};
	struct sepol_module_package *mod_pkg = NULL;
	const char *ifile = NULL;
	const char *ofile = NULL;
	FILE *in = NULL;
	FILE *out = NULL;
	int outfd = -1;

	// ignore sigpipe so we can check the return code of write, and potentially
	// return a more helpful error message
	signal(SIGPIPE, SIG_IGN);

	progname = basename(argv[0]);

	while ((opt = getopt_long(argc, argv, "h", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			usage(0);
		case '?':
		default:
			usage(1);
		}
	}

	if (argc >= optind + 1 && strcmp(argv[1], "-") != 0) {
		ifile = argv[1];
		in = fopen(ifile, "rb");
		if (in == NULL) {
			log_err("Failed to open %s: %s", ifile, strerror(errno));
			rc = -1;
			goto exit;
		}
	} else {
		ifile = "stdin";
		in = stdin;
	}

	if (argc >= optind + 2 && strcmp(argv[2], "-") != 0) {
		ofile = argv[2];
		out = fopen(ofile, "w");
		if (out == NULL) {
			log_err("Failed to open %s: %s", ofile, strerror(errno));
			rc = -1;
			goto exit;
		}
	} else {
		out = stdout;
	}

	if (argc >= optind + 3) {
		log_err("Too many arguments");
		usage(1);
	}

	rc = sepol_ppfile_to_module_package(in, &mod_pkg);
	if (rc != 0) {
		goto exit;
	}
	fclose(in);
	in = NULL;

	if (ofile) {
		char *mod_name = mod_pkg->policy->p.name;
		char *cil_path = strdup(ofile);
		if (cil_path == NULL) {
			log_err("No memory available for strdup\n");
			rc = -1;
			goto exit;
		}
		char *cil_name = basename(cil_path);
		char *separator = strrchr(cil_name, '.');
		if (separator) {
			*separator = '\0';
		}
		if (mod_name && strcmp(mod_name, cil_name) != 0) {
			fprintf(stderr,	"Warning: SELinux userspace will refer to the module from %s as %s rather than %s\n", ifile, mod_name, cil_name);
		}
		free(cil_path);
	}

	rc = sepol_module_package_to_cil(out, mod_pkg);
	if (rc != 0) {
		goto exit;
	}

exit:
	if (in != NULL) {
		fclose(in);
	}
	if (out != NULL) {
		fclose(out);
	}
	if (outfd != -1) {
		close(outfd);
		if (rc != 0) {
			unlink(argv[2]);
		}
	}
	sepol_module_package_free(mod_pkg);

	return rc;
}
