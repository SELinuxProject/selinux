#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <getopt.h>
#include <limits.h>
#include <selinux/selinux.h>
#include <sepol/sepol.h>

#include "../src/label_file.h"
#include "../src/regex.h"

static const char *policy_file;
static int ctx_err;

static int validate_context(char **ctxp)
{
	char *ctx = *ctxp;

	if (policy_file && sepol_check_context(ctx) < 0) {
		ctx_err = -1;
		return ctx_err;
	}

	return 0;
}

static int process_file(struct selabel_handle *rec, const char *filename)
{
	unsigned int line_num;
	int rc;
	char *line_buf = NULL;
	size_t line_len = 0;
	FILE *context_file;
	const char *prefix = NULL;

	context_file = fopen(filename, "r");
	if (!context_file) {
		fprintf(stderr, "Error opening %s: %s\n",
			    filename, strerror(errno));
		return -1;
	}

	line_num = 0;
	rc = 0;
	while (getline(&line_buf, &line_len, context_file) > 0) {
		rc = process_line(rec, filename, prefix, line_buf, ++line_num);
		if (rc || ctx_err) {
			/* With -p option need to check and fail if ctx err as
			 * process_line() context validation on Linux does not
			 * return an error, but does print the error line to
			 * stderr. Android will set both to error and print
			 * the error line. */
			rc = -1;
			goto out;
		}
	}
out:
	free(line_buf);
	fclose(context_file);
	return rc;
}

/*
 * File Format
 *
 * u32 - magic number
 * u32 - version
 * u32 - length of pcre version EXCLUDING nul
 * char - pcre version string EXCLUDING nul
 * u32 - number of stems
 * ** Stems
 *	u32  - length of stem EXCLUDING nul
 *	char - stem char array INCLUDING nul
 * u32 - number of regexs
 * ** Regexes
 *	u32  - length of upcoming context INCLUDING nul
 *	char - char array of the raw context
 *	u32  - length of the upcoming regex_str
 *	char - char array of the original regex string including the stem.
 *	u32  - mode bits for >= SELINUX_COMPILED_FCONTEXT_MODE
 *	       mode_t for <= SELINUX_COMPILED_FCONTEXT_PCRE_VERS
 *	s32  - stemid associated with the regex
 *	u32  - spec has meta characters
 *	u32  - The specs prefix_len if >= SELINUX_COMPILED_FCONTEXT_PREFIX_LEN
 *	u32  - data length of the pcre regex
 *	char - a buffer holding the raw pcre regex info
 *	u32  - data length of the pcre regex study daya
 *	char - a buffer holding the raw pcre regex study data
 */
static int write_binary_file(struct saved_data *data, int fd,
			     int do_write_precompregex)
{
	struct spec *specs = data->spec_arr;
	FILE *bin_file;
	size_t len;
	uint32_t magic = SELINUX_MAGIC_COMPILED_FCONTEXT;
	uint32_t section_len;
	uint32_t i;
	int rc;
	const char *reg_version;
	const char *reg_arch;

	bin_file = fdopen(fd, "w");
	if (!bin_file) {
		perror("fopen output_file");
		exit(EXIT_FAILURE);
	}

	/* write some magic number */
	len = fwrite(&magic, sizeof(uint32_t), 1, bin_file);
	if (len != 1)
		goto err;

	/* write the version */
	section_len = SELINUX_COMPILED_FCONTEXT_MAX_VERS;
	len = fwrite(&section_len, sizeof(uint32_t), 1, bin_file);
	if (len != 1)
		goto err;

	/* write version of the regex back-end */
	reg_version = regex_version();
	if (!reg_version)
		goto err;
	section_len = strlen(reg_version);
	len = fwrite(&section_len, sizeof(uint32_t), 1, bin_file);
	if (len != 1)
		goto err;
	len = fwrite(reg_version, sizeof(char), section_len, bin_file);
	if (len != section_len)
		goto err;

	/* write regex arch string */
	reg_arch = regex_arch_string();
	if (!reg_arch)
		goto err;
	section_len = strlen(reg_arch);
	len = fwrite(&section_len, sizeof(uint32_t), 1, bin_file);
	if (len != 1)
		goto err;
	len = fwrite(reg_arch, sizeof(char), section_len, bin_file);
	if (len != section_len)
		goto err;

	/* write the number of stems coming */
	section_len = data->num_stems;
	len = fwrite(&section_len, sizeof(uint32_t), 1, bin_file);
	if (len != 1)
		goto err;

	for (i = 0; i < section_len; i++) {
		char *stem = data->stem_arr[i].buf;
		uint32_t stem_len = data->stem_arr[i].len;

		/* write the strlen (aka no nul) */
		len = fwrite(&stem_len, sizeof(uint32_t), 1, bin_file);
		if (len != 1)
			goto err;

		/* include the nul in the file */
		stem_len += 1;
		len = fwrite(stem, sizeof(char), stem_len, bin_file);
		if (len != stem_len)
			goto err;
	}

	/* write the number of regexes coming */
	section_len = data->nspec;
	len = fwrite(&section_len, sizeof(uint32_t), 1, bin_file);
	if (len != 1)
		goto err;

	for (i = 0; i < section_len; i++) {
		char *context = specs[i].lr.ctx_raw;
		char *regex_str = specs[i].regex_str;
		mode_t mode = specs[i].mode;
		size_t prefix_len = specs[i].prefix_len;
		int32_t stem_id = specs[i].stem_id;
		struct regex_data *re = specs[i].regex;
		uint32_t to_write;

		/* length of the context string (including nul) */
		to_write = strlen(context) + 1;
		len = fwrite(&to_write, sizeof(uint32_t), 1, bin_file);
		if (len != 1)
			goto err;

		/* original context strin (including nul) */
		len = fwrite(context, sizeof(char), to_write, bin_file);
		if (len != to_write)
			goto err;

		/* length of the original regex string (including nul) */
		to_write = strlen(regex_str) + 1;
		len = fwrite(&to_write, sizeof(uint32_t), 1, bin_file);
		if (len != 1)
			goto err;

		/* original regex string */
		len = fwrite(regex_str, sizeof(char), to_write, bin_file);
		if (len != to_write)
			goto err;

		/* binary F_MODE bits */
		to_write = mode;
		len = fwrite(&to_write, sizeof(uint32_t), 1, bin_file);
		if (len != 1)
			goto err;

		/* stem for this regex (could be -1) */
		len = fwrite(&stem_id, sizeof(stem_id), 1, bin_file);
		if (len != 1)
			goto err;

		/* does this spec have a metaChar? */
		to_write = specs[i].hasMetaChars;
		len = fwrite(&to_write, sizeof(to_write), 1, bin_file);
		if (len != 1)
			goto err;

		/* For SELINUX_COMPILED_FCONTEXT_PREFIX_LEN */
		to_write = prefix_len;
		len = fwrite(&to_write, sizeof(to_write), 1, bin_file);
		if (len != 1)
			goto err;

		/* Write regex related data */
		rc = regex_writef(re, bin_file, do_write_precompregex);
		if (rc < 0)
			goto err;
	}

	rc = 0;
out:
	fclose(bin_file);
	return rc;
err:
	rc = -1;
	goto out;
}

static void free_specs(struct saved_data *data)
{
	struct spec *specs = data->spec_arr;
	unsigned int num_entries = data->nspec;
	unsigned int i;

	for (i = 0; i < num_entries; i++) {
		free(specs[i].lr.ctx_raw);
		free(specs[i].lr.ctx_trans);
		free(specs[i].regex_str);
		free(specs[i].type_str);
		regex_data_free(specs[i].regex);
	}
	free(specs);

	num_entries = data->num_stems;
	for (i = 0; i < num_entries; i++)
		free(data->stem_arr[i].buf);
	free(data->stem_arr);

	memset(data, 0, sizeof(*data));
}

static __attribute__ ((__noreturn__)) void usage(const char *progname)
{
	fprintf(stderr,
	    "usage: %s [-o out_file] [-p policy_file] fc_file\n"
	    "Where:\n\t"
	    "-o       Optional file name of the PCRE formatted binary\n\t"
	    "         file to be output. If not specified the default\n\t"
	    "         will be fc_file with the .bin suffix appended.\n\t"
	    "-p       Optional binary policy file that will be used to\n\t"
	    "         validate contexts defined in the fc_file.\n\t"
	    "-r       Omit precompiled regular expressions from the output.\n\t"
	    "         (PCRE2 only. Compiled PCRE2 regular expressions are\n\t"
	    "         not portable across architectures. Use this flag\n\t"
	    "         if you know that you build for an incompatible\n\t"
	    "         architecture to save space. When linked against\n\t"
	    "         PCRE1 this flag is ignored.)\n\t"
	    "-i       Print regular expression info end exit. That is, back\n\t"
	    "         end version and architecture identifier.\n\t"
	    "         Arch identifier format (PCRE2):\n\t"
	    "         <pointer width>-<size type width>-<endianness>, e.g.,\n\t"
	    "         \"8-8-el\" for x86_64.\n\t"
	    "fc_file  The text based file contexts file to be processed.\n",
	    progname);
		exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	const char *path = NULL;
	const char *out_file = NULL;
	int do_write_precompregex = 1;
	char stack_path[PATH_MAX + 1];
	char *tmp = NULL;
	int fd, rc, opt;
	FILE *policy_fp = NULL;
	struct stat buf;
	struct selabel_handle *rec = NULL;
	struct saved_data *data = NULL;

	if (argc < 2)
		usage(argv[0]);

	while ((opt = getopt(argc, argv, "io:p:r")) > 0) {
		switch (opt) {
		case 'o':
			out_file = optarg;
			break;
		case 'p':
			policy_file = optarg;
			break;
		case 'r':
			do_write_precompregex = 0;
			break;
		case 'i':
			printf("%s (%s)\n", regex_version(),
					regex_arch_string());
			return 0;
		default:
			usage(argv[0]);
		}
	}

	if (optind >= argc)
		usage(argv[0]);

	path = argv[optind];
	if (stat(path, &buf) < 0) {
		fprintf(stderr, "%s: could not stat: %s: %s\n", argv[0], path, strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Open binary policy if supplied. */
	if (policy_file) {
		policy_fp = fopen(policy_file, "r");

		if (!policy_fp) {
			fprintf(stderr, "%s: failed to open %s: %s\n",
				argv[0], policy_file, strerror(errno));
			exit(EXIT_FAILURE);
		}

		if (sepol_set_policydb_from_file(policy_fp) < 0) {
			fprintf(stderr, "%s: failed to load policy from %s\n",
				argv[0], policy_file);
			fclose(policy_fp);
			exit(EXIT_FAILURE);
		}
	}

	/* Generate dummy handle for process_line() function */
	rec = (struct selabel_handle *)calloc(1, sizeof(*rec));
	if (!rec) {
		fprintf(stderr, "%s: calloc failed: %s\n", argv[0], strerror(errno));
		if (policy_fp)
			fclose(policy_fp);
		exit(EXIT_FAILURE);
	}
	rec->backend = SELABEL_CTX_FILE;

	/* Need to set validation on to get the bin file generated by the
	 * process_line function, however as the bin file being generated
	 * may not be related to the currently loaded policy (that it
	 * would be validated against), then set callback to ignore any
	 * validation - unless the -p option is used in which case if an
	 * error is detected, the process will be aborted. */
	rec->validating = 1;
	selinux_set_callback(SELINUX_CB_VALIDATE,
			    (union selinux_callback)&validate_context);

	data = (struct saved_data *)calloc(1, sizeof(*data));
	if (!data) {
		fprintf(stderr, "%s: calloc failed: %s\n", argv[0], strerror(errno));
		free(rec);
		if (policy_fp)
			fclose(policy_fp);
		exit(EXIT_FAILURE);
	}

	rec->data = data;

	rc = process_file(rec, path);
	if (rc < 0) {
		fprintf(stderr, "%s: process_file failed\n", argv[0]);
		goto err;
	}

	rc = sort_specs(data);
	if (rc) {
		fprintf(stderr, "%s: sort_specs failed\n", argv[0]);
		goto err;
	}

	if (out_file)
		rc = snprintf(stack_path, sizeof(stack_path), "%s", out_file);
	else
		rc = snprintf(stack_path, sizeof(stack_path), "%s.bin", path);

	if (rc < 0 || rc >= (int)sizeof(stack_path)) {
		fprintf(stderr, "%s: snprintf failed\n", argv[0]);
		goto err;
	}

	tmp = malloc(strlen(stack_path) + 7);
	if (!tmp) {
		fprintf(stderr, "%s: malloc failed: %s\n", argv[0], strerror(errno));
		goto err;
	}

	rc = sprintf(tmp, "%sXXXXXX", stack_path);
	if (rc < 0) {
		fprintf(stderr, "%s: sprintf failed\n", argv[0]);
		goto err;
	}

	fd  = mkstemp(tmp);
	if (fd < 0) {
		fprintf(stderr, "%s: mkstemp %s failed: %s\n", argv[0], tmp, strerror(errno));
		goto err;
	}

	rc = fchmod(fd, buf.st_mode);
	if (rc < 0) {
		fprintf(stderr, "%s: fchmod %s failed: %s\n", argv[0], tmp, strerror(errno));
		goto err_unlink;
	}

	rc = write_binary_file(data, fd, do_write_precompregex);
	if (rc < 0) {
		fprintf(stderr, "%s: write_binary_file %s failed\n", argv[0], tmp);
		goto err_unlink;
	}

	rc = rename(tmp, stack_path);
	if (rc < 0) {
		fprintf(stderr, "%s: rename %s -> %s failed: %s\n", argv[0], tmp, stack_path, strerror(errno));
		goto err_unlink;
	}

	rc = 0;
out:
	if (policy_fp)
		fclose(policy_fp);

	free_specs(data);
	free(rec);
	free(data);
	free(tmp);
	return rc;

err_unlink:
	unlink(tmp);
err:
	rc = -1;
	goto out;
}
