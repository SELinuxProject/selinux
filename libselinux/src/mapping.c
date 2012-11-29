/*
 * Class and permission mappings.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <selinux/selinux.h>
#include <selinux/avc.h>
#include "mapping.h"

/*
 * Class and permission mappings
 */

struct selinux_mapping {
	security_class_t value; /* real, kernel value */
	unsigned num_perms;
	access_vector_t perms[sizeof(access_vector_t) * 8];
};

static struct selinux_mapping *current_mapping = NULL;
static security_class_t current_mapping_size = 0;

/*
 * Mapping setting function
 */

int
selinux_set_mapping(struct security_class_mapping *map)
{
	size_t size = sizeof(struct selinux_mapping);
	security_class_t i, j;
	unsigned k;

	free(current_mapping);
	current_mapping = NULL;
	current_mapping_size = 0;

	if (avc_reset() < 0)
		goto err;

	/* Find number of classes in the input mapping */
	if (!map) {
		errno = EINVAL;
		goto err;
	}
	i = 0;
	while (map[i].name)
		i++;

	/* Allocate space for the class records, plus one for class zero */
	current_mapping = (struct selinux_mapping *)calloc(++i, size);
	if (!current_mapping)
		goto err;

	/* Store the raw class and permission values */
	j = 0;
	while (map[j].name) {
		struct security_class_mapping *p_in = map + (j++);
		struct selinux_mapping *p_out = current_mapping + j;

		p_out->value = string_to_security_class(p_in->name);
		if (!p_out->value)
			goto err2;

		k = 0;
		while (p_in->perms[k]) {
			/* An empty permission string skips ahead */
			if (!*p_in->perms[k]) {
				k++;
				continue;
			}
			p_out->perms[k] = string_to_av_perm(p_out->value,
							    p_in->perms[k]);
			if (!p_out->perms[k])
				goto err2;
			k++;
		}
		p_out->num_perms = k;
	}

	/* Set the mapping size here so the above lookups are "raw" */
	current_mapping_size = i;
	return 0;
err2:
	free(current_mapping);
	current_mapping = NULL;
	current_mapping_size = 0;
err:
	return -1;
}

/*
 * Get real, kernel values from mapped values
 */

security_class_t
unmap_class(security_class_t tclass)
{
	if (tclass < current_mapping_size)
		return current_mapping[tclass].value;

	/* If here no mapping set or the class requested is not valid. */
	if (current_mapping_size != 0) {
		errno = EINVAL;
		return 0;
	}
	else
		return tclass;
}

access_vector_t
unmap_perm(security_class_t tclass, access_vector_t tperm)
{
	if (tclass < current_mapping_size) {
		unsigned i;
		access_vector_t kperm = 0;

		for (i=0; i<current_mapping[tclass].num_perms; i++)
			if (tperm & (1<<i)) {
				kperm |= current_mapping[tclass].perms[i];
				tperm &= ~(1<<i);
			}
		return kperm;
	}

	/* If here no mapping set or the perm requested is not valid. */
	if (current_mapping_size != 0) {
		errno = EINVAL;
		return 0;
	}
	else
		return tperm;
}

/*
 * Get mapped values from real, kernel values
 */

security_class_t
map_class(security_class_t kclass)
{
	security_class_t i;

	for (i=0; i<current_mapping_size; i++)
		if (current_mapping[i].value == kclass)
			return i;

/* If here no mapping set or the class requested is not valid. */
	if (current_mapping_size != 0) {
		errno = EINVAL;
		return 0;
	}
	else
		return kclass;
}

access_vector_t
map_perm(security_class_t tclass, access_vector_t kperm)
{
	if (tclass < current_mapping_size) {
		unsigned i;
		access_vector_t tperm = 0;

		for (i=0; i<current_mapping[tclass].num_perms; i++)
			if (kperm & current_mapping[tclass].perms[i]) {
				tperm |= 1<<i;
				kperm &= ~current_mapping[tclass].perms[i];
			}

		if (tperm == 0) {
			errno = EINVAL;
			return 0;
		}
		else
			return tperm;
	}
	return kperm;
}

void
map_decision(security_class_t tclass, struct av_decision *avd)
{
	if (tclass < current_mapping_size) {
		unsigned i;
		access_vector_t result;

		for (i=0, result=0; i<current_mapping[tclass].num_perms; i++)
			if (avd->allowed & current_mapping[tclass].perms[i])
				result |= 1<<i;
		avd->allowed = result;

		for (i=0, result=0; i<current_mapping[tclass].num_perms; i++)
			if (avd->decided & current_mapping[tclass].perms[i])
				result |= 1<<i;
		avd->decided = result;

		for (i=0, result=0; i<current_mapping[tclass].num_perms; i++)
			if (avd->auditallow & current_mapping[tclass].perms[i])
				result |= 1<<i;
		avd->auditallow = result;

		for (i=0, result=0; i<current_mapping[tclass].num_perms; i++)
			if (avd->auditdeny & current_mapping[tclass].perms[i])
				result |= 1<<i;
		avd->auditdeny = result;
	}
}
