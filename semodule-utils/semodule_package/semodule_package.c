/* Authors: Karl MacMillan <kmacmillan@tresys.com>
 *
 * Copyright (C) 2004 Tresys Technology, LLC
 *	This program is free software; you can redistribute it and/or modify
 *  	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, version 2.
 */

#include <sepol/module.h>
#include <getopt.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>

static void usage(const char *prog)
{
	printf("usage: %s -o <output file> -m <module> [-f <file contexts>]\n",
	       prog);
	printf("Options:\n");
	printf("  -o --outfile		Output file (required)\n");
	printf("  -m --module		Module file (required)\n");
	printf("  -f --fc		File contexts file\n");
	printf("  -s --seuser		Seusers file (only valid in base)\n");
	printf
	    ("  -u --user_extra	user_extra file (only valid in base)\n");
	printf("  -n --nc		Netfilter contexts file\n");
	printf("  -h --help		Show this help message\n");
}

static int file_to_data(const char *path, char **data, size_t * len, const char *progname)
{
	int fd;
	struct stat sb;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "%s:  Failed to open %s:  %s\n", progname, path,
			strerror(errno));
		return -1;
	}
	if (fstat(fd, &sb) < 0) {
		fprintf(stderr, "%s:  Failed to fstat %s:  %s\n", progname,
			path, strerror(errno));
		goto err;
	}
	if (!sb.st_size) {
		close(fd);
		*len = 0;
		return 0;
	}

	*data = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (*data == MAP_FAILED) {
		fprintf(stderr, "%s:  Failed to mmap %s:  %s\n", progname, path,
			strerror(errno));
		goto err;
	}
	*len = sb.st_size;
	close(fd);
	return 0;
      err:
	close(fd);
	return -1;
}

int main(int argc, char **argv)
{
	struct sepol_module_package *pkg = NULL;
	struct sepol_policy_file *mod = NULL, *out = NULL;
	FILE *fp = NULL;
	char *module = NULL, *file_contexts = NULL, *seusers =
	    NULL, *user_extra = NULL;
	char *fcdata = NULL, *outfile = NULL, *seusersdata =
	    NULL, *user_extradata = NULL;
	char *netfilter_contexts = NULL, *ncdata = NULL;
	size_t fclen = 0, seuserslen = 0, user_extralen = 0, nclen = 0;
	int i, ret;

	const struct option opts[] = {
		{"module", required_argument, NULL, 'm'},
		{"fc", required_argument, NULL, 'f'},
		{"seuser", required_argument, NULL, 's'},
		{"user_extra", required_argument, NULL, 'u'},
		{"nc", required_argument, NULL, 'n'},
		{"outfile", required_argument, NULL, 'o'},
		{"help", 0, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	while ((i = getopt_long(argc, argv, "m:f:s:u:o:n:h", opts, NULL)) != -1) {
		switch (i) {
		case 'h':
			usage(argv[0]);
			return EXIT_SUCCESS;
		case 'm':
			if (module) {
				fprintf(stderr,
					"May not specify more than one module\n");
				return EXIT_FAILURE;
			}
			module = strdup(optarg);
			if (!module) {
				fprintf(stderr, "%s:  Out of memory\n", argv[0]);
				return EXIT_FAILURE;
			}
			break;
		case 'f':
			if (file_contexts) {
				fprintf(stderr,
					"May not specify more than one file context file\n");
				return EXIT_FAILURE;
			}
			file_contexts = strdup(optarg);
			if (!file_contexts) {
				fprintf(stderr, "%s:  Out of memory\n", argv[0]);
				return EXIT_FAILURE;
			}
			break;
		case 'o':
			if (outfile) {
				fprintf(stderr,
					"May not specify more than one output file\n");
				return EXIT_FAILURE;
			}
			outfile = strdup(optarg);
			if (!outfile) {
				fprintf(stderr, "%s:  Out of memory\n", argv[0]);
				return EXIT_FAILURE;
			}
			break;
		case 's':
			if (seusers) {
				fprintf(stderr,
					"May not specify more than one seuser file\n");
				return EXIT_FAILURE;
			}
			seusers = strdup(optarg);
			if (!seusers) {
				fprintf(stderr, "%s:  Out of memory\n", argv[0]);
				return EXIT_FAILURE;
			}
			break;
		case 'u':
			if (user_extra) {
				fprintf(stderr,
					"May not specify more than one user_extra file\n");
				return EXIT_FAILURE;
			}
			user_extra = strdup(optarg);
			if (!user_extra) {
				fprintf(stderr, "%s:  Out of memory\n", argv[0]);
				return EXIT_FAILURE;
			}
			break;
		case 'n':
			if (netfilter_contexts) {
				fprintf(stderr,
					"May not specify more than one netfilter contexts file\n");
				return EXIT_FAILURE;
			}
			netfilter_contexts = strdup(optarg);
			if (!netfilter_contexts) {
				fprintf(stderr, "%s:  Out of memory\n", argv[0]);
				return EXIT_FAILURE;
			}
			break;
		default:
			usage(argv[0]);
			return EXIT_FAILURE;
		}
	}

	if (optind < argc) {
		fprintf(stderr, "%s:  Superfluous command line arguments: ", argv[0]);
		while (optind < argc)
			 fprintf(stderr, "%s ", argv[optind++]);
		fprintf(stderr, "\n");
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	if (!module || !outfile) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	if (file_contexts && file_to_data(file_contexts, &fcdata, &fclen, argv[0]))
		goto failure;

	if (seusers && file_to_data(seusers, &seusersdata, &seuserslen, argv[0]))
		goto failure;

	if (user_extra && file_to_data(user_extra, &user_extradata, &user_extralen, argv[0]))
		goto failure;

	if (netfilter_contexts && file_to_data(netfilter_contexts, &ncdata, &nclen, argv[0]))
		goto failure;

	if (sepol_policy_file_create(&mod)) {
		fprintf(stderr, "%s:  Out of memory\n", argv[0]);
		goto failure;
	}

	fp = fopen(module, "re");
	if (!fp) {
		fprintf(stderr, "%s:  Could not open file %s:  %s\n", argv[0],
			module, strerror(errno));
		goto failure;
	}
	sepol_policy_file_set_fp(mod, fp);

	if (sepol_module_package_create(&pkg)) {
		fprintf(stderr, "%s:  Out of memory\n", argv[0]);
		goto failure;
	}

	if (sepol_policydb_read(sepol_module_package_get_policy(pkg), mod)) {
		fprintf(stderr,
			"%s:  Error while reading policy module from %s\n",
			argv[0], module);
		goto failure;
	}

	fclose(fp);
	fp = NULL;

	if (fclen && sepol_module_package_set_file_contexts(pkg, fcdata, fclen)) {
		fprintf(stderr, "%s:  Error while setting file contexts\n", argv[0]);
		goto failure;
	}

	if (seuserslen && sepol_module_package_set_seusers(pkg, seusersdata, seuserslen)) {
		fprintf(stderr, "%s:  Error while setting seusers\n", argv[0]);
		goto failure;
	}

	if (user_extra && sepol_module_package_set_user_extra(pkg, user_extradata, user_extralen)) {
		fprintf(stderr, "%s:  Error while setting extra users\n", argv[0]);
		goto failure;
	}

	if (nclen && sepol_module_package_set_netfilter_contexts(pkg, ncdata, nclen)) {
		fprintf(stderr, "%s:  Error while setting netfilter contexts\n", argv[0]);
		goto failure;
	}

	if (sepol_policy_file_create(&out)) {
		fprintf(stderr, "%s:  Out of memory\n", argv[0]);
		goto failure;
	}

	fp = fopen(outfile, "we");
	if (!fp) {
		fprintf(stderr, "%s:  Could not open file %s:  %s\n", argv[0],
			outfile, strerror(errno));
		goto failure;
	}
	sepol_policy_file_set_fp(out, fp);

	if (sepol_module_package_write(pkg, out)) {
		fprintf(stderr,
			"%s:  Error while writing module package to %s\n",
			argv[0], argv[1]);
		goto failure;
	}

	ret = fclose(fp);
	fp = NULL;
	if (ret) {
		fprintf(stderr, "%s:  Could not close file %s:  %s\n", argv[0],
			outfile, strerror(errno));
		goto failure;
	}

	ret = EXIT_SUCCESS;
	goto cleanup;

failure:
	ret = EXIT_FAILURE;

cleanup:
	if (fp)
		fclose(fp);
	sepol_policy_file_free(out);
	if (nclen)
		munmap(ncdata, nclen);
	if (user_extradata)
		munmap(user_extradata, user_extralen);
	if (seuserslen)
		munmap(seusersdata, seuserslen);
	if (fclen)
		munmap(fcdata, fclen);
	sepol_module_package_free(pkg);
	sepol_policy_file_free(mod);
	free(netfilter_contexts);
	free(user_extra);
	free(seusers);
	free(outfile);
	free(file_contexts);
	free(module);

	return ret;
}
