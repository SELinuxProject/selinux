#include <ctype.h>
#include <errno.h>
#include <pcre.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <linux/limits.h>

#include "../src/label_file.h"

static int process_file(struct saved_data *data, const char *filename)
{
	struct spec *spec;
	unsigned int line_num;
	char *line_buf = NULL;
	size_t line_len;
	ssize_t len;
	FILE *context_file;

	context_file = fopen(filename, "r");
	if (!context_file) {
		fprintf(stderr, "Error opening %s: %s\n", filename, strerror(errno));
		return -1;
	}

	line_num = 0;
	while ((len = getline(&line_buf, &line_len, context_file)) != -1) {
		char *context;
		char *mode;
		char *regex;
		char *cp, *anchored_regex;
		char *buf_p;
		pcre *re;
		pcre_extra *sd;
		const char *err;
		int items, erroff, rc;
		size_t regex_len;
		int32_t stem_id;

		len = strlen(line_buf);
		if (line_buf[len - 1] == '\n')
			line_buf[len - 1] = 0;
		buf_p = line_buf;
		while (isspace(*buf_p))
			buf_p++;
		/* Skip comment lines and empty lines. */
		if (*buf_p == '#' || *buf_p == 0)
			continue;

		items = sscanf(line_buf, "%ms %ms %ms", &regex, &mode, &context);
		if (items < 2 || items > 3) {
			fprintf(stderr, "invalid entry, skipping:%s", line_buf);
			continue;
		}

		if (items == 2) {
			context = mode;
			mode = NULL;
		}

		rc = grow_specs(data);
		if (rc) {
			fprintf(stderr, "grow_specs failed: %s\n", strerror(errno));
			return rc;
		}

		spec = &data->spec_arr[data->nspec];

		spec->lr.ctx_raw = context;
		spec->mode = string_to_mode(mode);
		if (spec->mode == (mode_t)-1) {
			fprintf(stderr, "%s: line %u has invalid file type %s\n",
				regex, line_num + 1, mode);
			spec->mode = 0;
		}
		free(mode);
		spec->regex_str = regex;

		stem_id = find_stem_from_spec(data, regex);
		spec->stem_id = stem_id;
		/* skip past the fixed stem part */
		if (stem_id != -1)
			regex += data->stem_arr[stem_id].len;

		regex_len = strlen(regex);
		cp = anchored_regex = malloc(regex_len + 3);
		if (!cp) {
			fprintf(stderr, "Malloc Failed: %s\n", strerror(errno));
			return -1;
		}
		*cp++ = '^';
		memcpy(cp, regex, regex_len);
		cp += regex_len;
		*cp++ = '$';
		*cp = '\0';

		spec_hasMetaChars(spec);

		re = pcre_compile(anchored_regex, PCRE_DOTALL, &err, &erroff, NULL);
		if (!re) {
			fprintf(stderr, "PCRE compilation failed for %s at offset %d: %s\n", anchored_regex, erroff, err);
			return -1;
		}
		spec->regex = re;

		sd = pcre_study(re, 0, &err);
		if (!sd) {
			fprintf(stderr, "PCRE study failed for %s: %s\n", anchored_regex, err);
			return -1;
		}
		free(anchored_regex);
		spec->sd = sd;

		line_num++;
		data->nspec++;
	}

	free(line_buf);
	fclose(context_file);

	return 0;
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
 * 	u32  - length of stem EXCLUDING nul
 * 	char - stem char array INCLUDING nul
 * u32 - number of regexs
 * ** Regexes
 * 	u32  - length of upcoming context INCLUDING nul
 * 	char - char array of the raw context
 *	u32  - length of the upcoming regex_str
 *	char - char array of the original regex string including the stem.
 *	mode_t - mode bits
 *	s32  - stemid associated with the regex
 *	u32  - spec has meta characters
 *	u32  - data length of the pcre regex
 *	char - a bufer holding the raw pcre regex info
 *	u32  - data length of the pcre regex study daya
 *	char - a buffer holding the raw pcre regex study data
 */
static int write_binary_file(struct saved_data *data, int fd)
{
	struct spec *specs = data->spec_arr;
	FILE *bin_file;
	size_t len;
	uint32_t magic = SELINUX_MAGIC_COMPILED_FCONTEXT;
	uint32_t section_len;
	uint32_t i;
	int rc;

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

	/* write the pcre version */
	section_len = strlen(pcre_version());
	len = fwrite(&section_len, sizeof(uint32_t), 1, bin_file);
	if (len != 1)
		goto err;
	len = fwrite(pcre_version(), sizeof(char), section_len, bin_file);
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
		int32_t stem_id = specs[i].stem_id;
		pcre *re = specs[i].regex;
		pcre_extra *sd = get_pcre_extra(&specs[i]);
		uint32_t to_write;
		size_t size;

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
		len = fwrite(&mode, sizeof(mode), 1, bin_file);
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

		/* determine the size of the pcre data in bytes */
		rc = pcre_fullinfo(re, NULL, PCRE_INFO_SIZE, &size);
		if (rc < 0)
			goto err;

		/* write the number of bytes in the pcre data */
		to_write = size;
		len = fwrite(&to_write, sizeof(uint32_t), 1, bin_file);
		if (len != 1)
			goto err;

		/* write the actual pcre data as a char array */
		len = fwrite(re, 1, to_write, bin_file);
		if (len != to_write)
			goto err;

		/* determine the size of the pcre study info */
		rc = pcre_fullinfo(re, sd, PCRE_INFO_STUDYSIZE, &size);
		if (rc < 0)
			goto err;

		/* write the number of bytes in the pcre study data */
		to_write = size;
		len = fwrite(&to_write, sizeof(uint32_t), 1, bin_file);
		if (len != 1)
			goto err;

		/* write the actual pcre study data as a char array */
		len = fwrite(sd->study_data, 1, to_write, bin_file);
		if (len != to_write)
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

static int free_specs(struct saved_data *data)
{
	struct spec *specs = data->spec_arr;
	unsigned int num_entries = data->nspec;
	unsigned int i;

	for (i = 0; i < num_entries; i++) {
		free(specs[i].lr.ctx_raw);
		free(specs[i].lr.ctx_trans);
		free(specs[i].regex_str);
		pcre_free(specs[i].regex);
		pcre_free_study(specs[i].sd);
	}
	free(specs);

	num_entries = data->num_stems;
	for (i = 0; i < num_entries; i++) {
		free(data->stem_arr[i].buf);
	}
	free(data->stem_arr);

	memset(data, 0, sizeof(*data));
	return 0;
}

int main(int argc, char *argv[])
{
	struct saved_data data;
	const char *path;
	char stack_path[PATH_MAX + 1];
	int rc;
	char *tmp= NULL;
	int fd;
	struct stat buf;

	if (argc != 2) {
		fprintf(stderr, "usage: %s input_file\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	memset(&data, 0, sizeof(data));

	path = argv[1];

	if (stat(path, &buf) < 0) {
		fprintf(stderr, "Can not stat: %s: %m\n", path);
		exit(EXIT_FAILURE);
	}

	rc = process_file(&data, path);
	if (rc < 0)
		return rc;

	rc = sort_specs(&data);
	if (rc)
		return rc;

	rc = snprintf(stack_path, sizeof(stack_path), "%s.bin", path);
	if (rc < 0 || rc >= (int)sizeof(stack_path))
		return rc;

	if (asprintf(&tmp, "%sXXXXXX", stack_path) < 0)
		return -1;

	fd  = mkstemp(tmp);
	if (fd < 0)
		goto err;

	rc = fchmod(fd, buf.st_mode);
	if (rc < 0) {
		perror("fchmod failed to set permission on compiled regexs");
		goto err;
	}

	rc = write_binary_file(&data, fd);

	if (rc < 0)
		goto err;

	rename(tmp, stack_path);
	rc = free_specs(&data);
	if (rc < 0)
		goto err;

	rc = 0;
out:
	free(tmp);
	return rc;
err:
	rc = -1;
	goto out;
}
