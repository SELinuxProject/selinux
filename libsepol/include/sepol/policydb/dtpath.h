#ifndef _SEPOL_POLICYDB_DTPATH_H_
#define _SEPOL_POLICYDB_DTPATH_H_

#include <stdbool.h>
#include <ctype.h>
#include <string.h>

/*
 * Allowed characters in a devicetree node-name / unit-address,
 * per the Devicetree Specification: [0-9a-zA-Z,._+-]
 */
static inline bool is_valid_dt_char(char c)
{
	return isalnum((unsigned char)c) || c == ',' || c == '.' || c == '_' ||
	       c == '+' || c == '-';
}

/*
 * is_valid_devicetree_path - validate a devicetree node path
 * @path: NUL-terminated path string, e.g. "/soc/uart@10000000"
 *
 * Rules enforced (per the Devicetree Specification):
 *   - path must be non-NULL and non-empty
 *   - path must start with '/'
 *   - "/" (root) alone is valid
 *   - path must not end with '/' unless it is exactly "/"
 *   - no empty segments (i.e. "//" is invalid)
 *   - each segment is "node-name" or "node-name@unit-address"
 *   - node-name: 1-31 characters from [0-9a-zA-Z,._+-]
 *   - unit-address (if present): 1+ characters from [0-9a-zA-Z,._+-]
 *   - at most one '@' per segment
 *
 * Returns true if the path is well-formed, false otherwise.
 */
static inline bool is_valid_dt_path(const char *path)
{
	if (path == NULL || path[0] == '\0')
		return false;

	if (path[0] != '/')
		return false;

	/* Root node alone is valid */
	if (strcmp(path, "/") == 0)
		return true;

	/* No trailing slash allowed (except for root, handled above) */
	size_t len = strlen(path);
	if (path[len - 1] == '/')
		return false;

	const char *seg_start = path + 1; /* skip leading '/' */

	while (*seg_start != '\0') {
		const char *seg_end = strchr(seg_start, '/');
		size_t seg_len = seg_end ? (size_t)(seg_end - seg_start) :
					   strlen(seg_start);

		if (seg_len == 0)
			return false; /* empty segment, e.g. from "//" */

		const char *at = memchr(seg_start, '@', seg_len);
		size_t name_len = at ? (size_t)(at - seg_start) : seg_len;

		/* node-name must be 1-31 characters */
		if (name_len == 0 || name_len > 31)
			return false;

		/* node-name must start with a lower or uppercase character */
		if (!isalpha((unsigned char)seg_start[0]))
			return false;

		for (size_t i = 0; i < name_len; i++) {
			if (!is_valid_dt_char(seg_start[i]))
				return false;
		}

		if (at) {
			const char *addr_start = at + 1;
			size_t addr_len = seg_len - name_len - 1;

			if (addr_len == 0)
				return false; /* '@' with nothing after it */

			for (size_t i = 0; i < addr_len; i++) {
				/* also rejects a second '@' in the same segment */
				if (!is_valid_dt_char(addr_start[i]))
					return false;
			}
		}

		if (!seg_end)
			break;
		seg_start = seg_end + 1;
	}

	return true;
}

#endif /* _SEPOL_POLICYDB_DTPATH_H_ */
