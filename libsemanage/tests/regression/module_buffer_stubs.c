#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <semanage/modules.h>

static int check_data(const char *data, size_t len)
{
	if (len == 6 && !memcmp(data, "reject", len)) {
		errno = EACCES;
		return -1;
	}
	assert(len == 4 && !memcmp(data, "a\0\xffz", len));
	return 0;
}

int __wrap_semanage_module_install(semanage_handle_t *handle, char *data,
				   size_t len, const char *name,
				   const char *ext)
{
	(void)handle;
	assert(!strcmp(name, "name") && !strcmp(ext, "cil"));
	return check_data(data, len);
}

int __wrap_semanage_module_install_info(semanage_handle_t *handle,
					const semanage_module_info_t *info,
					char *data, size_t len)
{
	(void)handle;
	(void)info;
	return check_data(data, len);
}
